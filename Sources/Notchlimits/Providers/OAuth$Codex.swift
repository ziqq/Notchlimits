import Foundation
import CryptoKit

/// Продление входа Codex по refresh-токену из auth.json.
///
/// Запрос собран ровно как в codex-rs (login/src/auth/manager.rs,
/// `request_chatgpt_token_refresh`): POST JSON на auth.openai.com с
/// grant_type, refresh_token и публичным client_id — секрета в нём нет.
///
/// В отличие от Claude, refresh-токен здесь одноразовый: повторное
/// использование сервер считает утечкой (`refresh_token_reused`) и отзывает
/// вход. Поэтому продлеваем только спящие входы — те, что сейчас не в
/// `~/.codex`, где ими владеют приложение и CLI (см. `Renewal$Codex`).
enum OAuth$Codex {

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
        /// Сервер явно отказал во временной ошибке, не выдав новые токены.
        case unavailable
        /// Ответ потерян или не разобран: прежний refresh-токен мог быть потрачен.
        case uncertain
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
            return .uncertain
        case .success(let response):
            switch response.status {
            case 200:
                guard let tokens = parse(response.data) else { return .uncertain }
                return .success(tokens)
            case 401:
                return .rejected
            case 400:
                // Как в CLI: окончательно только invalid_grant и явные коды
                // про refresh-токен, прочие 400 — временная беда.
                return isPermanent(response.data) ? .rejected : .unavailable
            case 500...599:
                return .uncertain
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
actor Renewal$Codex {

    static let shared = Renewal$Codex()

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
        /// Потерянный ответ нельзя восстановить повтором того же токена.
        case uncertain
    }

    private struct Pending {
        let renewal: AuthSwap$Codex.Renewal
        let usedRefreshToken: String
        let tokens: OAuth$Codex.Tokens
    }

    private struct Attempt {
        let result: Result
        let identity: String?
    }

    /// Учитываем и запрос в полёте: actor допускает другой вызов на время await.
    private var attempts: [String: Attempt] = [:]
    private static let attemptsKey = "codexRefreshAttempts"
    private var attemptsDirty = false
    /// Живая копия после ротации, если запись auth.json не удалась.
    private var pending: [String: Pending] = [:]
    private var inFlight: Set<UUID> = []
    private var terminating = false

    /// `force` — продлить, даже если срок ещё не подошёл (usage ответил 401).
    func renew(columnID: String, home: URL, force: Bool,
               expected: AuthSwap$Codex.AuthSnapshot? = nil) async -> Result {
        if let saved = pending[columnID] {
            if let result = persist(saved, columnID: columnID, home: home) { return result }
        }
        if let (pendingID, saved) = pending.first(where: {
            $0.key != columnID && AuthSwap$Codex.recoveryMatches($0.value.renewal, columnID: columnID, home: home)
        }) {
            if let result = persist(saved, columnID: pendingID, home: home, currentColumnID: columnID) { return result }
        }
        guard !terminating else { return .skipped }
        let renewal: AuthSwap$Codex.Renewal
        do {
            guard let source = try AuthSwap$Codex.beginRenewal(columnID: columnID, home: home, expected: expected) else { return .skipped }
            renewal = source
        } catch { return .unavailable }
        defer {
            if pending[columnID]?.renewal.id != renewal.id { AuthSwap$Codex.finishRenewal(renewal) }
        }
        guard let refreshToken = Self.refreshToken(in: renewal.record.data),
              Self.shouldRenew(isBaseHome: false,
                               expiresAt: Provider$Codex.parseAuth(renewal.record.data)?.expiresAt,
                               force: force, now: Date())
        else { return .skipped }
        let grant = Self.grantIdentity(refreshToken)
        if let attempt = savedAttempt(for: grant) {
            return currentResult(attempt, renewal: renewal, home: home)
        }
        let identity = AuthSwap$Codex.authIdentity(renewal.record.data)
        // Commit the quarantine before sending a one-use grant. A failed
        // preference write must not spend a token that restart could replay.
        guard recordAttempt(Attempt(result: .uncertain, identity: identity), for: grant) else {
            recordAttempt(nil, for: grant)
            return .unavailable
        }
        attempts[grant] = Attempt(result: .unavailable, identity: identity)
        inFlight.insert(renewal.id)
        defer { inFlight.remove(renewal.id) }

        let response = await OAuth$Codex.refresh(refreshToken: refreshToken)
        // Grant reuse depends on the server response, even when removal retired
        // its destination. Only a known temporary refusal permits another POST.
        switch response {
        case .success, .uncertain:
            recordAttempt(Attempt(result: .uncertain, identity: identity), for: grant)
        case .rejected:
            recordAttempt(Attempt(result: .rejected, identity: identity), for: grant)
        case .unavailable:
            recordAttempt(nil, for: grant)
        }
        guard AuthSwap$Codex.isCurrent(renewal) else { return .skipped }
        switch response {
        case .success(let tokens):
            let saved = Pending(renewal: renewal, usedRefreshToken: refreshToken, tokens: tokens)
            pending[columnID] = saved
            return persist(saved, columnID: columnID, home: home) ?? .skipped
        case .rejected:
            return currentResult(Attempt(result: .rejected, identity: identity), renewal: renewal, home: home)
        case .unavailable:
            return .unavailable
        case .uncertain:
            return currentResult(Attempt(result: .uncertain, identity: identity), renewal: renewal, home: home)
        }
    }

    /// Quarantine the grant across homes, but report failure only for the session
    /// that submitted it. A fresh CLI access token can still serve usage even
    /// when its unchanged refresh grant cannot safely be posted again.
    private func currentResult(_ attempt: Attempt, renewal: AuthSwap$Codex.Renewal, home: URL) -> Result {
        guard attempt.result == .uncertain || attempt.result == .rejected else { return attempt.result }
        guard let identity = attempt.identity else { return .unavailable }
        let snapshot = AuthSwap$Codex.AuthSnapshot(data: renewal.record.data, key: renewal.key,
            generation: renewal.generation, columnGeneration: renewal.columnGeneration,
            sourceKey: renewal.sourceKey, sourceGeneration: renewal.sourceGeneration)
        do {
            return try AuthSwap$Codex.isCurrent(snapshot, columnID: renewal.columnID, home: home)
                && AuthSwap$Codex.authIdentity(renewal.record.data) == identity
                ? attempt.result : .renewed
        } catch {
            return .unavailable
        }
    }

    private static func grantIdentity(_ token: String) -> String {
        SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func savedAttempt(for grant: String) -> Attempt? {
        if let attempt = attempts[grant] { return attempt }
        guard let value = UserDefaults.standard.dictionary(forKey: Self.attemptsKey)?[grant] else { return nil }
        let record = value as? [String: String]
        let attempt = Attempt(result: record?["result"] == "rejected" ? .rejected : .uncertain,
                              identity: record?["identity"])
        attempts[grant] = attempt
        return attempt
    }

    @discardableResult
    private func recordAttempt(_ attempt: Attempt?, for grant: String) -> Bool {
        attempts[grant] = attempt
        var records = UserDefaults.standard.dictionary(forKey: Self.attemptsKey) ?? [:]
        if let attempt {
            var record = ["result": attempt.result == .rejected ? "rejected" : "uncertain"]
            record["identity"] = attempt.identity
            records[grant] = record
        } else { records[grant] = nil }
        if records.isEmpty { UserDefaults.standard.removeObject(forKey: Self.attemptsKey) }
        else { UserDefaults.standard.set(records, forKey: Self.attemptsKey) }
        attemptsDirty = !UserDefaults.standard.synchronize()
        return !attemptsDirty
    }

    /// Drain accepted refresh requests and retry persistence without another POST.
    /// Keep the process alive if the only rotated grant is still in memory.
    func prepareForTermination(timeout: TimeInterval = 25) async -> Bool {
        terminating = true
        let deadline = Date().addingTimeInterval(timeout)
        while !inFlight.isEmpty || !pending.isEmpty {
            for (columnID, saved) in pending { _ = persist(saved, columnID: columnID) }
            if inFlight.isEmpty && pending.isEmpty { break }
            guard Date() < deadline else { terminating = false; return false }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        do { try AuthSwap$Codex.flushCopies() }
        catch { terminating = false; return false }
        if attemptsDirty {
            guard UserDefaults.standard.synchronize() else { terminating = false; return false }
            attemptsDirty = false
        }
        return true
    }

    func cancelTermination() { terminating = false }

    /// A changed login or retired generation discards only its own pending response.
    private func persist(_ saved: Pending, columnID: String, home: URL? = nil,
                         currentColumnID: String? = nil) -> Result? {
        do {
            let stored = try AuthSwap$Codex.storeRenewed(saved.renewal,
                                                       usedRefreshToken: saved.usedRefreshToken,
                                                       tokens: saved.tokens)
            if pending[columnID]?.renewal.id == saved.renewal.id { pending[columnID] = nil }
            AuthSwap$Codex.finishRenewal(saved.renewal)
            if let stored {
                let attempt = saved.tokens.refreshToken.flatMap {
                    $0 != saved.usedRefreshToken
                        ? Attempt(result: .uncertain, identity: AuthSwap$Codex.authIdentity(saved.renewal.record.data)) : nil
                }
                recordAttempt(attempt, for: Self.grantIdentity(saved.usedRefreshToken))
                // Durability for a previous owner does not renew the current
                // login after the same logical column has been redirected.
                if let home,
                   try !AuthSwap$Codex.isCurrent(stored, columnID: currentColumnID ?? columnID, home: home) { return nil }
                return .renewed
            }
            // Потраченный токен не используем, даже если его копия осталась в другом профиле.
            recordAttempt(Attempt(result: .uncertain, identity: AuthSwap$Codex.authIdentity(saved.renewal.record.data)),
                          for: Self.grantIdentity(saved.usedRefreshToken))
            return nil
        } catch {
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
        guard let data = try? AuthSwap$Codex.authData(home: file.deletingLastPathComponent()) else { return nil }
        return refreshToken(in: data)
    }

    private static func refreshToken(in data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (root["auth_mode"] as? String).map({ $0 == "chatgpt" }) ?? true,
              let tokens = root["tokens"] as? [String: Any],
              let token = tokens["refresh_token"] as? String, !token.isEmpty
        else { return nil }
        return token
    }
}
