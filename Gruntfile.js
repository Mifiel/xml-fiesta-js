module.exports = function (grunt) {
  require('load-grunt-tasks')(grunt);
  const pkg = grunt.file.readJSON('package.json');

  grunt.initConfig({
    pkg,

    mochaTest: {
      test: {
        options: {
          reporter: 'spec',
          require: 'ts-node/register',
          exlude: ['spec'],
        },
        src: ['spec/*.ts'],
      },
    },

    watch: {
      clear: {
        files: ['src/*.ts', 'spec/*.ts'],
      },
      scripts: {
        files: ['src/*.ts', 'spec/*.ts'],
        tasks: ['clear', 'mochaTest'],
        options: {},
      },
    },

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

  grunt.registerTask('default', ['watch']);
  grunt.registerTask('test', ['mochaTest']);
};
