import AppKit
import SwiftUI

struct UpdateDialogView: View {
    let icon: NSImage
    let title: String
    let message: String
    let installTitle: String
    let skipTitle: String
    let onInstall: () -> Void
    let onSkip: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 16) {
                Image(nsImage: icon)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 56, height: 56)
                    .accessibilityHidden(true)
                    .padding(.bottom, 4)
                Text(title)
                    .font(.system(size: 13, weight: .bold))
                    .accessibilityAddTraits(.isHeader)
                Text(message)
                    .font(.system(size: 13))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 6)

            VStack(spacing: 6) {
                Button(installTitle, action: onInstall)
                    .buttonStyle(UpdateActionStyle(isDefault: true))
                    .keyboardShortcut(.defaultAction)
                Button(skipTitle, action: onSkip)
                    .buttonStyle(UpdateActionStyle(isDefault: false))
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 24)
        .padding(.bottom, 16)
        .frame(width: 304)
        .background {
            RoundedRectangle(cornerRadius: 28)
                .fill(Color(nsColor: .windowBackgroundColor))
                .overlay {
                    RoundedRectangle(cornerRadius: 28)
                        .strokeBorder(.primary.opacity(0.10), lineWidth: 1)
                }
        }
    }
}

private struct UpdateActionStyle: ButtonStyle {
    let isDefault: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(isDefault ? Color.white : Color.primary)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .frame(maxWidth: .infinity, minHeight: 28)
            .background(isDefault
                        ? Color(nsColor: .controlAccentColor).opacity(configuration.isPressed ? 0.75 : 1)
                        : Color.primary.opacity(configuration.isPressed ? 0.15 : 0.07), in: Capsule())
            .contentShape(Capsule())
    }
}
