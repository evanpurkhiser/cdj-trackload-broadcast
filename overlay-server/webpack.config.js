module.exports = {
  entry: "./overlay.js",
  output: { filename: "app.js" },
  module: {
    loaders: [{
      test:   /\.js$/,
      loader: 'babel-loader',
      query: {
        presets: ['es2015', 'react'],
        plugins: ['transform-object-assign'],
      },
    },
    {
      test: /\.scss$/,
      loaders: ['style', 'css', 'sass'],
    }],
  }
};
