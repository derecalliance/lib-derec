const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

const projectRoot = __dirname;
const repoRoot = path.resolve(projectRoot, '../..');

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * `@derec-alliance/react-native` is installed from `../../packages/react-native`,
 * so `node_modules/@derec-alliance/react-native` is a symlink pointing outside
 * this project. Metro follows the symlink but will not serve files it is not
 * watching, so the package has to be named in `watchFolders` — otherwise the
 * bundle fails with "Unable to resolve module" even though the native build
 * succeeded. A consumer installing the published package from npm needs none of
 * this; it is purely an artefact of testing against the local checkout.
 *
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const config = {
  watchFolders: [path.resolve(repoRoot, 'packages/react-native')],
  resolver: {
    nodeModulesPaths: [path.resolve(projectRoot, 'node_modules')],
  },
};

module.exports = mergeConfig(getDefaultConfig(projectRoot), config);
