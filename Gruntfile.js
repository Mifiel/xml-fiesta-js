module.exports = function (grunt) {
  require('load-grunt-tasks')(grunt);
  const pkg = grunt.file.readJSON('package.json');

  grunt.initConfig({
    pkg,

    bump: {
      options: {
        files: ['package.json', 'README.md'],
        updateConfigs: [],
        commit: true,
        commitMessage: 'Bump version v%VERSION%',
        commitFiles: ['package.json', 'README.md'],
        createTag: false,
        push: false,
        gitDescribeOptions: '--tags --always --abbrev=1',
        regExp: new RegExp(
          '([\'|\"]?version[\'|\"]?[ ]*[:|=][ ]*[\'|\"]?)(\\d+\\.\\d+\\.\\d+(-\\.\\d+)?(-\\d+)?)[\\d||A-a|.|-]*([\'|\"]?)', 'i'
        )
      }
    },
  });

  grunt.registerTask('default', function () {
    grunt.log.writeln('Use `yarn test` or `yarn test:watch` for tests; `grunt bump` for version bumps.');
  });
};
