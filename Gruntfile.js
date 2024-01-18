module.exports = function(grunt) {
  require('load-grunt-tasks')(grunt);
  const pkg = grunt.file.readJSON('package.json');

  grunt.initConfig({
    pkg,

    mochaTest: {
      test: {
        options: {
          reporter: "spec",
          require: "ts-node/register",
          exlude: ["spec"],
        },
        src: ["spec/*.ts"],
      },
    },

    coveralls: {
      options: {
        // dont fail ci if coveralls.io is down
        force: false,
      },
      test: {
        src: "coverage/lcov.info",
      },
    },

    watch: {
      clear: {
        files: ["src/*.ts", "spec/*ts"],
      },
      // tasks: ['clear']
      scripts: {
        files: ["src/*.ts", "spec/*ts"],
        tasks: ["clear", "mochaTest"],
        options: {},
      },
    },

    browserify: {
      dist: {
        options: {
          browserifyOptions: {
            standalone: "XMLFiesta",
          },
        },
        src: "lib/xml-fiesta.js",
        dest: "dist/xml-fiesta.js",
      },
    },

    ts: {
      default: {
        tsconfig: "./tsconfig.json",
        src: ["src/**/*.ts", "!node_modules/**"],
      },
    },

    bump: {
      options: {
        files: ["package.json", "bower.json", "README.md"],
        updateConfigs: [],
        commit: true,
        commitMessage: "Bump version v%VERSION%",
        commitFiles: ["package.json", "bower.json", "README.md"],
        createTag: false,
        push: false,
        gitDescribeOptions: "--tags --always --abbrev=1",
        regExp: new RegExp(
          "(['|\"]?version['|\"]?[ ]*[:|=][ ]*['|\"]?)(\\d+\\.\\d+\\.\\d+(-\\.\\d+)?(-\\d+)?)[\\d||A-a|.|-]*(['|\"]?)",
          "i"
        ),
      },
    },

    clean: {
      dist: ["dist", "lib"],
    },
  });

  grunt.registerTask('default', ['watch']);
  grunt.registerTask('build', ['clean', 'ts', 'browserify']);
  grunt.registerTask('test', ['mochaTest']);
};
