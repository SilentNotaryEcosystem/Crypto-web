const path = require('path');
const webpack= require('webpack');

module.exports = {
    entry: './index.js',
    output: {
        filename: 'my-first-webpack.bundle.js',
    },
    module: {
        rules: [{ test: /\.txt$/, use: 'raw-loader' }],
    },
//    plugins: [
//        new webpack.LoaderOptionsPlugin({
//            // test: /\.xxx$/, // may apply this only for some modules
//            options: {
//                stream: require.resolve("stream-browserify"),
//                buffer: require.resolve("buffer/")
//            }
//        })
//    ],
};
