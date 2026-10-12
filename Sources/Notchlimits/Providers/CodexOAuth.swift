import Foundation

/// Продление входа Codex по refresh-токену из auth.json.
///
/// Запрос собран ровно как в codex-rs (login/src/auth/manager.rs,
/// `request_chatgpt_token_refresh`): POST JSON на auth.openai.com с
/// grant_type, refresh_token и публичным client_id — секрета в нём нет.
///
/// В отличие от Claude, refresh-токен здесь одноразовый: повторное
/// использование сервер считает утечкой (`refresh_token_reused`) и отзывает
/// вход. Поэтому продлеваем только спящие входы — те, что сейчас не в
/// `~/.codex`, где ими владеют приложение и CLI (см. `CodexRenewal`).
enum CodexOAuth {

    static let tokenURL = URL(string: "https://auth.openai.com/oauth/token")!
    static let clientID = "app_EMoamEEZ73f0CkXaXp7hrann"

    struct Tokens {
        let idToken: String?
        let accessToken: String
        /// nil — сервер не выдал новый, прежний остаётся.
        let refreshToken: String?
    }

    enum Outcome {
        case success(Tokens)
        /// Токен протух, отозван или уже использован — нужен новый вход.
        case rejected
        /// Сеть, таймаут, 5xx: не приговор, попробуем позже.
        case unavailable
    }

    static func refresh(refreshToken: String) async -> Outcome {
        let body: [String: Any] = [
            "client_id": clientID,
            "grant_type": "refresh_token",
            "refresh_token": refreshToken
        ]

        // Без ретрая: если сервер токен уже принял, а ответ потерялся, повтор
        // тем же токеном — это `refresh_token_reused` и отзыв входа.
        switch await HTTPClient.shared.post(tokenURL, headers: ["Accept": "application/json"],
                                            json: body, retry: false) {
        case .failure:
            return .unavailable
        case .success(let response):
            switch response.status {
            case 200:
                guard let tokens = parse(response.data) else { return .unavailable }
                return .success(tokens)
            case 401:
                return .rejected
            case 400:
                // Как в CLI: окончательно только invalid_grant и явные коды
                // про refresh-токен, прочие 400 — временная беда.
                return isPermanent(response.data) ? .rejected : .unavailable
            default:
                return .unavailable
            }
        }
    }

    /// Разбор ответа. Чистая функция — покрыта самопроверкой без сети.
    static func parse(_ data: Data) -> Tokens? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let accessToken = root["access_token"] as? String, !accessToken.isEmpty
        else { return nil }
        func nonEmpty(_ key: String) -> String? {
            (root[key] as? String).flatMap { $0.isEmpty ? nil : $0 }
        }
        return Tokens(idToken: nonEmpty("id_token"),
                      accessToken: accessToken,
                      refreshToken: nonEmpty("refresh_token"))
    }

    /// Код ошибки бывает строкой в `error`, полем `error.code` или `code`.
    static func isPermanent(_ data: Data) -> Bool {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        let code = (root["error"] as? String)
            ?? ((root["error"] as? [String: Any])?["code"] as? String)
            ?? (root["code"] as? String)
        guard let code = code?.lowercased() else { return false }
        return code == "invalid_grant" || code.hasPrefix("refresh_token_")
    }
}

/// Держит спящие входы Codex свежими.
///
/// Access-токен Codex живёт 10 дней, а продлевает его только тот, кто им
/// пользуется. Профиль, на который приложение давно не переключали, тихо
/// протухал, и чтобы его оживить, приходилось переключать приложение —
/// с перезапуском и оборванными задачами. Теперь продлеваем сами, заранее.
actor CodexRenewal {

    static let shared = CodexRenewal()

    /// CLI продлевает раз в 8 дней из 10 — то есть за 2 дня до конца.
    static let window: TimeInterval = 2 * 24 * 3600

    enum Result {
        /// Вход свежий (продлили мы или кто-то другой).
        case renewed
        /// Продлевать не нужно или не нам.
        case skipped
        /// Refresh-токен отвергнут — поможет только новый вход.
        case rejected
        /// Сервер недоступен — попробуем на следующем цикле.
        case unavailable
    }

    /// Refresh-токены, которые сервер уже отверг: слать их снова бессмысленно.
    private var rejected: Set<String> = []

    /// `force` — продлить, даже если срок ещё не подошёл (usage ответил 401).
    func renew(columnID: String, home: URL, force: Bool) async -> Result {
        let live = CodexAuthSwap.liveHome(columnID: columnID, home: home)
        let file = live.appendingPathComponent("auth.json")
        guard let refreshToken = Self.refreshToken(file),
              Self.shouldRenew(isBaseHome: CodexAuthSwap.isBaseHome(live),
                               expiresAt: CodexProvider.readAuth(codexHome: live)?.expiresAt,
                               force: force, now: Date())
        else { return .skipped }
        guard !rejected.contains(refreshToken) else { return .rejected }

        switch await CodexOAuth.refresh(refreshToken: refreshToken) {
        case .success(let tokens):
            do {
                try CodexAuthSwap.storeRenewed(columnID: columnID, home: home,
                                               usedRefreshToken: refreshToken, tokens: tokens)
            } catch {
                // Токен уже потрачен, а записать не вышло. Колонка всё равно
                // узнает правду на ближайшем запросе usage.
                return .unavailable
            }
            return .renewed
        case .rejected:
            // Пока мы ходили, файл мог обновить CLI в этом профиле.
            let current = CodexAuthSwap.liveHome(columnID: columnID, home: home)
            if let latest = Self.refreshToken(current.appendingPathComponent("auth.json")),
               latest != refreshToken {
                return .renewed
            }
            rejected.insert(refreshToken)
            return .rejected
        case .unavailable:
            return .unavailable
        }
    }

    /// Продлевать ли вход. Чистая функция — покрыта самопроверкой.
    static func shouldRenew(isBaseHome: Bool, expiresAt: Date?, force: Bool, now: Date) -> Bool {
        // Вход в ~/.codex принадлежит приложению и голой `codex`: продлив его
        // сами, мы бы «сожгли» их refresh-токен. Даже по 401.
        guard !isBaseHome else { return false }
        if force { return true }
        // Срок не прочитать — не гадаем, ждём 401 от usage.
        guard let expiresAt else { return false }
        return expiresAt.timeIntervalSince(now) <= window
    }

    static func refreshToken(_ file: URL) -> String? {
        guard let data = try? Data(contentsOf: file),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (root["auth_mode"] as? String).map({ $0 == "chatgpt" }) ?? true,
              let tokens = root["tokens"] as? [String: Any],
              let token = tokens["refresh_token"] as? String, !token.isEmpty
        else { return nil }
        return token
    }
}
