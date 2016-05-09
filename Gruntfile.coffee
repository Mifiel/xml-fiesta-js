module.exports = (grunt) ->
  pkg = grunt.file.readJSON('package.json')

  grunt.initConfig {
    pkg: pkg

    mochaTest:
      test:
        options:
          reporter: 'spec'
          require: [
            'coffee-script/register'
            './coverage-reporter.coffee'
          ]
          exlude: ['spec']
        src: ['spec/*.coffee']

    watch:
      clear:
        files: ['**/**/*.coffee']
        # tasks: ['clear']
      scripts:
        files: ['**/**/*.coffee']
        tasks: ['clear', 'mochaTest', 'run:coverage']
        options: {}

    browserify:
      dist:
        options:
          browserifyOptions:
            standalone: 'XMLFiesta'
        src: 'lib/xml-fiesta.js'
        dest: 'dist/xml-fiesta.js'
      builds:
        options:
          browserifyOptions:
            standalone: 'XMLFiesta'
        src: 'lib/xml-fiesta.js'
        dest: "builds/xml-fiesta-#{pkg['version']}.js"

    coffee:
      all:
        expand: true
        flatten: true
        cwd: '.'
        src: ['src/*.coffee']
        dest: 'lib/'
        ext: '.js'

    bump:
      options:
        files: [
          'package.json'
          'bower.json'
          'README.md'
        ]
        updateConfigs: []
        commit: true
        commitMessage: 'Bump version v%VERSION%'
        commitFiles: [
          'package.json'
          'bower.json'
          'README.md'
        ],
        createTag: false
        push: false
        gitDescribeOptions: '--tags --always --abbrev=1'
        regExp: new RegExp(
          '([\'|\"]?version[\'|\"]?[ ]*[:|=][ ]*[\'|\"]?)(\\d+\\.\\d+\\.\\d+(-\\.\\d+)?(-\\d+)?)[\\d||A-a|.|-]*([\'|\"]?)', 'i'
        )

    clean:
      all: ['dist', 'lib', 'coverage']
      coverage: 'coverage'

    run:
      coverage:
        cmd: './node_modules/.bin/istanbul'
        args: [
          'report'
          'text-summary'
          'lcov'
        ]
  }

  grunt.event.on 'coverage', (lcovFileContents, done) ->
    # Check below on the section "The coverage event"
    done()

  grunt.loadNpmTasks('grunt-contrib-watch')
  grunt.loadNpmTasks('grunt-clear')
  grunt.loadNpmTasks('grunt-browserify')
  grunt.loadNpmTasks('grunt-contrib-coffee')
  grunt.loadNpmTasks('grunt-bump')
  grunt.loadNpmTasks('grunt-contrib-clean')
  grunt.loadNpmTasks('grunt-mocha-test')
  grunt.loadNpmTasks('grunt-run')

  grunt.registerTask('default', ['watch'])
  grunt.registerTask('build', ['clean', 'coffee', 'browserify'])
  grunt.registerTask('test', ['clean:coverage', 'mochaTest'])
