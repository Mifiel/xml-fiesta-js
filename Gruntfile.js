module.exports = function(grunt) {
  require('load-grunt-tasks')(grunt);
  const pkg = grunt.file.readJSON('package.json');

  grunt.initConfig({
    pkg,

    mochaTest: {
      test: {
        options: {
          reporter: 'spec',
          require: '@babel/register',
          exlude: ['spec']
        },
        src: ['spec/*.js']
      }
    },

    coveralls: {
      options: {
        // dont fail ci if coveralls.io is down
        force: false
      },
      test: {
        src: 'coverage/lcov.info'
      }
    },

    watch: {
      clear: {
        files: ['src/*.js', 'spec/*js']
      },
        // tasks: ['clear']
      scripts: {
        files: ['src/*.js', 'spec/*js'],
        tasks: ['clear', 'mochaTest'],
        options: {}
      }
    },

    browserify: {
      dist: {
        options: {
          browserifyOptions: {
            standalone: 'XMLFiesta'
          }
        },
        src: 'lib/xml-fiesta.js',
        dest: 'dist/xml-fiesta.js'
      }
    },

    babel: {
      options: {
        sourceMap: false
      },
      lib: {
        files: [{
          expand: true,
          cwd: 'src/',
          src: ['*.js'],
          dest: 'lib/'
        }]
      }
    },

    bump: {
      options: {
        files: [
          'package.json',
          'bower.json',
          'README.md'
        ],
        updateConfigs: [],
        commit: true,
        commitMessage: 'Bump version v%VERSION%',
        commitFiles: [
          'package.json',
          'bower.json',
          'README.md'
        ],
        createTag: false,
        push: false,
        gitDescribeOptions: '--tags --always --abbrev=1',
        regExp: new RegExp(
          '([\'|\"]?version[\'|\"]?[ ]*[:|=][ ]*[\'|\"]?)(\\d+\\.\\d+\\.\\d+(-\\.\\d+)?(-\\d+)?)[\\d||A-a|.|-]*([\'|\"]?)', 'i'
        )
      }
    },

    clean: {
      dist: ['dist'],
    }
  });

  grunt.registerTask('default', ['watch']);
  grunt.registerTask('build', ['clean', 'babel', 'browserify']);
  grunt.registerTask('test', ['mochaTest']);
};
