#!/usr/bin/env swift
//
// Генератор иконки приложения: Resources/AppIcon.icns
//
//   swift Tools/make-icon.swift
//
// Рисует то же, что показывает панель: чёрный вырез сверху и три полосы
// лимитов под ним — зелёная короткая, жёлтая средняя, красная длинная.
//
import AppKit

// MARK: - Палитра (та же, что в Theme.swift)

let green = NSColor(srgbRed: 0.30, green: 0.84, blue: 0.47, alpha: 1)
let yellow = NSColor(srgbRed: 0.98, green: 0.77, blue: 0.22, alpha: 1)
let red = NSColor(srgbRed: 0.98, green: 0.36, blue: 0.33, alpha: 1)

/// Прямоугольник со скруглением только снизу — форма выреза.
func bottomRounded(_ rect: NSRect, radius: CGFloat) -> NSBezierPath {
    let path = NSBezierPath()
    path.move(to: NSPoint(x: rect.minX, y: rect.maxY))
    path.line(to: NSPoint(x: rect.maxX, y: rect.maxY))
    path.line(to: NSPoint(x: rect.maxX, y: rect.minY + radius))
    path.curve(to: NSPoint(x: rect.maxX - radius, y: rect.minY),
               controlPoint1: NSPoint(x: rect.maxX, y: rect.minY),
               controlPoint2: NSPoint(x: rect.maxX, y: rect.minY))
    path.line(to: NSPoint(x: rect.minX + radius, y: rect.minY))
    path.curve(to: NSPoint(x: rect.minX, y: rect.minY + radius),
               controlPoint1: NSPoint(x: rect.minX, y: rect.minY),
               controlPoint2: NSPoint(x: rect.minX, y: rect.minY))
    path.close()
    return path
}

func draw(size: CGFloat) -> NSBitmapImageRep {
    let pixels = Int(size)
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil,
                               pixelsWide: pixels, pixelsHigh: pixels,
                               bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false,
                               colorSpaceName: .calibratedRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current?.imageInterpolation = .high

    let unit = size / 1024

    // Корпус иконки: 824×824 по центру холста 1024 — пропорции macOS.
    let body = NSRect(x: 100 * unit, y: 100 * unit, width: 824 * unit, height: 824 * unit)
    let corner = 185 * unit
    let squircle = NSBezierPath(roundedRect: body, xRadius: corner, yRadius: corner)

    // Мягкая тень под корпусом.
    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.45)
    shadow.shadowOffset = NSSize(width: 0, height: -14 * unit)
    shadow.shadowBlurRadius = 30 * unit
    shadow.set()
    NSColor.black.setFill()
    squircle.fill()
    NSGraphicsContext.restoreGraphicsState()

    NSGraphicsContext.saveGraphicsState()
    squircle.addClip()

    // Графитовый градиент корпуса.
    NSGradient(colors: [NSColor(srgbRed: 0.21, green: 0.22, blue: 0.26, alpha: 1),
                        NSColor(srgbRed: 0.07, green: 0.08, blue: 0.10, alpha: 1)])?
        .draw(in: body, angle: -90)

    // Вырез: чёрная форма, прижатая к верхней кромке корпуса.
    let notchWidth = 300 * unit
    let notchHeight = 104 * unit
    let notch = NSRect(x: body.midX - notchWidth / 2,
                       y: body.maxY - notchHeight,
                       width: notchWidth, height: notchHeight)
    NSColor.black.setFill()
    bottomRounded(notch, radius: 44 * unit).fill()

    // Полосы лимитов.
    let barHeight = 82 * unit
    let barGap = 58 * unit
    let trackX = body.minX + 116 * unit
    let trackWidth = body.width - 232 * unit
    let stackHeight = barHeight * 3 + barGap * 2
    // Центрируем стопку в свободной части корпуса под вырезом.
    var barTop = notch.minY - (notch.minY - body.minY - stackHeight) / 2

    for (color, fraction) in [(green, 0.34), (yellow, 0.62), (red, 0.92)] {
        let track = NSRect(x: trackX, y: barTop - barHeight, width: trackWidth, height: barHeight)
        NSColor.white.withAlphaComponent(0.10).setFill()
        NSBezierPath(roundedRect: track, xRadius: barHeight / 2, yRadius: barHeight / 2).fill()

        let fill = NSRect(x: track.minX, y: track.minY,
                          width: max(barHeight, track.width * fraction), height: barHeight)
        color.setFill()
        NSBezierPath(roundedRect: fill, xRadius: barHeight / 2, yRadius: barHeight / 2).fill()

        barTop -= barHeight + barGap
    }

    // Тонкий световой кант сверху — иконка перестаёт выглядеть плоской.
    NSColor.white.withAlphaComponent(0.13).setStroke()
    let rim = NSBezierPath(roundedRect: body.insetBy(dx: 1.5 * unit, dy: 1.5 * unit),
                           xRadius: corner, yRadius: corner)
    rim.lineWidth = 3 * unit
    rim.stroke()

    NSGraphicsContext.restoreGraphicsState()
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

// MARK: - Сборка .iconset → .icns

let fileManager = FileManager.default
let root = URL(fileURLWithPath: fileManager.currentDirectoryPath)
let iconset = root.appendingPathComponent("build/AppIcon.iconset")
try? fileManager.removeItem(at: iconset)
try fileManager.createDirectory(at: iconset, withIntermediateDirectories: true)

let variants: [(name: String, size: CGFloat)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024)
]

for variant in variants {
    let rep = draw(size: variant.size)
    guard let data = rep.representation(using: .png, properties: [:]) else {
        FileHandle.standardError.write(Data("не смог отрисовать \(variant.name)\n".utf8))
        exit(1)
    }
    try data.write(to: iconset.appendingPathComponent(variant.name + ".png"))
}

let resources = root.appendingPathComponent("Resources")
try? fileManager.createDirectory(at: resources, withIntermediateDirectories: true)
let output = resources.appendingPathComponent("AppIcon.icns")

let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["-c", "icns", iconset.path, "-o", output.path]
try process.run()
process.waitUntilExit()
guard process.terminationStatus == 0 else { exit(process.terminationStatus) }

print("готово: \(output.path)")
