const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");

module.exports = {
  entry: "./src/index.ts",
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: {
          loader: "ts-loader",
          options: {
            projectReferences: true,
          },
        },
        exclude: /node_modules/,
      },
      {
        test: /.css$/i,
        use: ["style-loader", "css-loader"],
      },
      {
        test: /\.wasm$/,
        type: "webassembly/async",
      },
    ],
  },
  resolve: {
    extensions: [".ts", ".js"],
    alias: {
      // Use webui's local wasm build (with parse_node enabled) instead of wasm-utxo's default build.
      // Both paths are needed: js/wasm for ts-loader project references, dist/esm/js/wasm for module resolution.
      [path.resolve(__dirname, "../wasm-utxo/js/wasm")]: path.resolve(__dirname, "wasm"),
      [path.resolve(__dirname, "../wasm-utxo/dist/esm/js/wasm")]: path.resolve(__dirname, "wasm"),
    },
  },
  output: {
    filename: "bundle.js",
    path: path.resolve(__dirname, "dist"),
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: "./src/index.html",
    }),
  ],
  mode: "development",
  experiments: {
    asyncWebAssembly: true,
  },
};
