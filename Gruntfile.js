module.exports = function(grunt) {
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
        files: ['**/**/*.js']
      },
        // tasks: ['clear']
      scripts: {
        files: ['**/**/*.js'],
        tasks: ['clear', 'mochaTest', 'run:coverage'],
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
        src: 'src/xml-fiesta.js',
        dest: 'dist/xml-fiesta.js'
      },
      builds: {
        options: {
          browserifyOptions: {
            standalone: 'XMLFiesta'
          }
        },
        src: 'src/xml-fiesta.js',
        dest: `builds/xml-fiesta-${pkg['version']}.js`
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

  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-clear');
  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-bump');
  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-coveralls');

  grunt.registerTask('default', ['watch']);
  grunt.registerTask('build', ['clean', 'browserify']);
  grunt.registerTask('test', ['mochaTest']);
};
