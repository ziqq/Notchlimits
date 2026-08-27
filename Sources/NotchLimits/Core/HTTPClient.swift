import Foundation

/// Сетевые запросы приложения — только официальные эндпоинты Anthropic и
/// OpenAI: usage у обоих плюс обновление OAuth-токена Anthropic.
/// Кэш URLSession отключён, куки не хранятся.
struct HTTPClient {

    static let shared = HTTPClient()

    private let session: URLSession

    private init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 20
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        session = URLSession(configuration: configuration)
    }

    struct Response {
        let status: Int
        let data: Data
        let retryAfter: TimeInterval?
    }

    enum Failure: Error {
        case transport(String)
    }

    /// GET с одним ретраем на сетевую ошибку или 5xx.
    func get(_ url: URL, headers: [String: String]) async -> Result<Response, Failure> {
        await send("GET", url, headers: headers, body: nil)
    }

    /// POST с телом JSON. Ретрай тот же, что у GET: обновление токена
    /// идемпотентно ровно до тех пор, пока сервер не ответил, — а 5xx и обрыв
    /// означают, что ответа не было.
    func post(_ url: URL, headers: [String: String], json: [String: Any]) async -> Result<Response, Failure> {
        guard let body = try? JSONSerialization.data(withJSONObject: json) else {
            return .failure(.transport(L.t("error.network")))
        }
        var merged = headers
        merged["Content-Type"] = "application/json"
        return await send("POST", url, headers: merged, body: body)
    }

    private func send(_ method: String, _ url: URL,
                      headers: [String: String], body: Data?) async -> Result<Response, Failure> {
        var lastError = L.t("error.unreachable")
        for attempt in 0..<2 {
            if attempt > 0 { try? await Task.sleep(nanoseconds: 800_000_000) }
            do {
                var request = URLRequest(url: url)
                request.httpMethod = method
                request.httpBody = body
                for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }

                let (data, response) = try await session.data(for: request)
                guard let http = response as? HTTPURLResponse else {
                    lastError = L.t("error.noHTTP")
                    continue
                }
                if (500...599).contains(http.statusCode), attempt == 0 {
                    lastError = L.t("error.http", http.statusCode)
                    continue
                }
                return .success(Response(status: http.statusCode,
                                         data: data,
                                         retryAfter: Self.retryAfter(http)))
            } catch {
                lastError = L.t((error as NSError).code == NSURLErrorTimedOut ? "error.timeout" : "error.network")
            }
        }
        return .failure(.transport(lastError))
    }

    private static func retryAfter(_ response: HTTPURLResponse) -> TimeInterval? {
        guard let raw = response.value(forHTTPHeaderField: "Retry-After") else { return nil }
        if let seconds = TimeInterval(raw.trimmingCharacters(in: .whitespaces)) { return max(seconds, 1) }
        // Формат HTTP-date.
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        guard let date = formatter.date(from: raw) else { return nil }
        return max(date.timeIntervalSinceNow, 1)
    }
}
