import Foundation

struct GrokProvider: UsageProvider {
    private struct Reply: Decodable {
        struct Billing: Decodable {
            struct Config: Decodable {
                struct Period: Decodable {
                    let type: String?
                    let end: String?
                }
                let creditUsagePercent: Double?
                let currentPeriod: Period?
                let billingPeriodEnd: String?
            }
            let config: Config?
            let subscription_tier: String?
        }

        struct RPCError: Decodable {
            let message: String
        }
        let result: Billing?
        let error: RPCError?
    }

    func fetch(_ account: DiscoveredAccount) async -> FetchOutcome {
        guard case .grokAuth(let auth) = account.source else {
            return .failure(L.t("error.unknownSource"))
        }
        guard let binary = BinaryLocator.grok() else {
            return .failure(L.t("setup.missing.title", "grok"))
        }
        return await Task.detached(priority: .utility) {
            do {
                var environment = ProcessInfo.processInfo.environment
                environment["GROK_AUTH_PATH"] = auth.path
                let process = try UsageProcess(binary: binary, arguments: ["agent", "--no-leader", "stdio"],
                                               environment: environment)
                let deadline = DispatchTime.now() + 25
                func request(_ id: Int, _ method: String, params: [String: Any] = [:]) throws -> Data {
                    try process.send(["jsonrpc": "2.0", "id": id, "method": method, "params": params])
                    while true {
                        let data = try process.line(until: deadline)
                        if let reply = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                           reply["id"] as? Int == id {
                            if id == 1, reply["result"] == nil { throw UsageProcess.Failure.invalidOutput }
                            return data
                        }
                    }
                }
                _ = try request(1, "initialize", params: [
                    "protocolVersion": 1, "clientCapabilities": [:],
                    "clientInfo": ["name": "Notchlimits", "version": "1"]
                ])
                return Self.parse(try request(2, "_x.ai/billing"))
            } catch UsageProcess.Failure.timeout {
                return .failure(L.t("error.timeout"))
            } catch {
                return .failure(L.t("error.network"))
            }
        }.value
    }

    static func parse(_ data: Data) -> FetchOutcome {
        guard let reply = try? JSONDecoder().decode(Reply.self, from: data) else {
            return .failure(L.t("error.parse"))
        }
        if reply.error?.message == "Authentication required" {
            return .reauth(L.t("column.reauth"))
        }
        guard let billing = reply.result, let config = billing.config else {
            return .failure(L.t("error.parse"))
        }
        let reset = (config.currentPeriod?.end ?? config.billingPeriodEnd).flatMap(Format.iso8601)
        let title: String
        switch config.currentPeriod?.type {
        case "USAGE_PERIOD_TYPE_WEEKLY": title = L.t("window.week")
        case "USAGE_PERIOD_TYPE_MONTHLY": title = L.t("window.monthTotal")
        default: title = L.t("window.generic")
        }
        if let percent = config.creditUsagePercent, (0...100).contains(percent) {
            let window = LimitWindow(key: config.currentPeriod?.type ?? "credits", title: title,
                                     utilization: percent, resetsAt: reset)
            return .success(UsageSnapshot(subtitle: billing.subscription_tier, windows: [window]))
        }
        guard let reset else { return .failure(L.t("error.parse")) }
        return .success(UsageSnapshot(subtitle: billing.subscription_tier, windows: [],
                                     stats: [UsageStat(key: "period", label: title, value: reset.formatted(date: .abbreviated, time: .shortened))]))
    }
}
