import SwiftUI
import UIKit

@main
struct OpenCsvBenchApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var output = "Tap Run. The benchmark takes seconds on desktop-class hardware — possibly minutes on device. It runs off the main thread."
    @State private var running = false

    var body: some View {
        VStack(spacing: 16) {
            Text("OpenCSV prover benchmark")
                .font(.headline)
            Button(running ? "Running…" : "Run") { runBenchmark() }
                .disabled(running)
            ScrollView {
                Text(output)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
        }
        .padding()
        .task {
            if !running {
                runBenchmark()
            }
        }
    }

    private func runBenchmark() {
        running = true
        UIApplication.shared.isIdleTimerDisabled = true
        DispatchQueue.global(qos: .userInitiated).async {
            var text: String
            if let ptr = opencsv_bench_run() {
                let raw = String(cString: ptr)
                print("OPENCSV_BENCH_RESULT \(raw)")
                text = Self.pretty(raw)
                opencsv_bench_free_string(ptr)
            } else {
                text = "opencsv_bench_run returned null"
            }
            DispatchQueue.main.async {
                output = text
                running = false
                UIApplication.shared.isIdleTimerDisabled = false
            }
        }
    }

    /// Minimal JSON pretty-printer for display; falls back to raw text.
    private nonisolated static func pretty(_ raw: String) -> String {
        guard let data = raw.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(
                  withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
              let str = String(data: pretty, encoding: .utf8)
        else { return raw }
        return str
    }
}
