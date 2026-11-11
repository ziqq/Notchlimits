import Foundation

struct KimiProvider: UsageProvider {
    private struct Envelope: Decodable {
        let code: Int
        let data: Payload?
    }

    private struct Payload: Decodable {
        let kind: String
        let status: Int?
        let quota: Quota?
    }

    private struct Quota: Decodable {
        struct Window: Decodable {
            let usedRatio: Double
            let resetAt: String?
        }
        let usages: [String: Window]
    }

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        guard case .kimiHome(let home) = account.source else {
            return .failure(L.t("error.unknownSource"))
        }
        guard let binary = BinaryLocator.kimi() else {
            return .failure(L.t("setup.missing.title", "kimi"))
        }
        return await Task.detached(priority: .utility) {
            do {
                var environment = ProcessInfo.processInfo.environment
                environment["KIMI_CODE_HOME"] = home.path
                let process = try UsageProcess(binary: binary,
                                               arguments: ["web", "--no-open", "--port", "\(Int.random(in: 49152...64000))"],
                                               environment: environment)
                // Use this child's own startup URL. Kimi may choose another port
                // if the requested one is already in use.
                let deadline = DispatchTime.now() + 8
                var port: Int?
                while port == nil {
                    let line = String(decoding: try process.line(until: deadline), as: UTF8.self)
                    let pattern = #"http://127\.0\.0\.1:[0-9]+/"#
                    if line.contains("Local:"), let range = line.range(of: pattern, options: .regularExpression) {
                        port = URL(string: String(line[range]))?.port
                    }
                }
                guard let port, let url = URL(string: "http://127.0.0.1:\(port)/api/v1/oauth/usage") else {
                    return .failure(L.t("error.parse"))
                }
                let token = try String(contentsOf: home.appendingPathComponent("server.token"), encoding: .utf8)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                guard !token.isEmpty else { return .failure(L.t("error.parse")) }

                let configuration = URLSessionConfiguration.ephemeral
                configuration.connectionProxyDictionary = [:]
                configuration.timeoutIntervalForRequest = 20
                configuration.timeoutIntervalForResource = 25
                let session = URLSession(configuration: configuration,
                                         delegate: LoopbackOnly(), delegateQueue: nil)
                defer {
                    session.invalidateAndCancel()
                    withExtendedLifetime(process) {}
                }
                var request = URLRequest(url: url)
                request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                let (data, response) = try await session.data(for: request)
                guard let http = response as? HTTPURLResponse else { return .failure(L.t("error.noHTTP")) }
                guard http.statusCode == 200 else { return .failure(L.t("error.http", http.statusCode)) }
                return Self.parse(data)
            } catch UsageProcess.Failure.timeout {
                return .failure(L.t("error.timeout"))
            } catch {
                return .failure(L.t("error.network"))
            }
        }.value
    }

    static func parse(_ data: Data) -> FetchOutcome {
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: data),
              envelope.code == 0, let payload = envelope.data else {
            return .failure(L.t("error.parse"))
        }
        if payload.kind == "error" {
            switch payload.status {
            case 401, 403: return .reauth(L.t("column.reauth"))
            case 429: return .rateLimited(retryAfter: nil)
            case let status?: return .failure(L.t("error.http", status))
            default: return .failure(L.t("error.network"))
            }
        }
        guard payload.kind == "ok", let quota = payload.quota else {
            return .failure(L.t("error.parse"))
        }
        let titles = [("limit5h", "window.fiveHour"), ("limit7d", "window.week"),
                      ("monthTotal", "window.monthTotal"), ("monthCode", "window.monthCode")]
        let windows = titles.compactMap { key, title -> LimitWindow? in
            guard let window = quota.usages[key], (0...1).contains(window.usedRatio) else { return nil }
            return LimitWindow(key: key, title: L.t(title), utilization: window.usedRatio * 100,
                               resetsAt: window.resetAt.flatMap(Format.iso8601))
        }
        guard !windows.isEmpty else { return .failure(L.t("error.parse")) }
        return .success(UsageSnapshot(windows: windows))
    }

    private final class LoopbackOnly: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }
}
