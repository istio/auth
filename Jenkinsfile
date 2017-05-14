#!groovy

@Library('testutils@stable-41b0bf6')

import org.istio.testutils.Utilities
import org.istio.testutils.GitUtilities
import org.istio.testutils.Bazel

// Utilities shared amongst modules
def gitUtils = new GitUtilities()
def utils = new Utilities()
def bazel = new Bazel()

mainFlow(utils) {
  node {
    gitUtils.initialize()
    bazel.setVars()
    env.ISTIO_VERSION = readFile('istio.RELEASE').trim()
  }
  // PR on master branch
  if (utils.runStage('PRESUBMIT')) {
    presubmit(gitUtils, bazel, utils)
  }
  // Postsubmit from master branch
  if (utils.runStage('POSTSUBMIT')) {
    postsubmit(gitUtils, bazel, utils)
  }
  // PR from master to stable branch for qualification
  if (utils.runStage('STABLE_PRESUBMIT')) {
    stablePresubmit(gitUtils, bazel, utils)
  }
  // Postsubmit form stable branch, post qualification
  if (utils.runStage('STABLE_POSTSUBMIT')) {
    stablePostsubmit(gitUtils, bazel, utils)
  }
}

def presubmit(gitUtils, bazel, utils) {
  goBuildNode(gitUtils, 'istio.io/auth') {
    stage('Bazel Build') {
      sh('bin/install-prereqs.sh')
      bazel.fetch('-k //...')
      bazel.build('//...')
    }
    stage('Go Build') {
      sh('bin/setup.sh')
    }
    stage('Bazel Tests') {
      bazel.test('//...')
    }
    stage('Code Check') {
      sh('bin/linters.sh')
      sh('bin/headers.sh')
    }
    stage('Code Coverage') {
      sh('bin/coverage.sh > codecov.report')
      sh('bazel-bin/bin/toolbox/presubmit/package_coverage_check')
      utils.publishCodeCoverage('AUTH_CODECOV_TOKEN')
    }
  }
}

def postsubmit(gitUtils, bazel, utils) {
  goBuildNode(gitUtils, 'istio.io/auth') {
    bazel.updateBazelRc()
    stage('Code Coverage') {
      bazel.fetch('-k //...')
      bazel.build('//...')
      sh('bin/setup.sh')
      bazel.test('//...')
      sh('bin/coverage.sh > codecov.report')
      sh('bin/coverage.sh')
      utils.publishCodeCoverage('AUTH_CODECOV_TOKEN')
    }
    utils.fastForwardStable('auth')
  }
}

def stablePresubmit(gitUtils, bazel, utils) {
  goBuildNode(gitUtils, 'istio.io/auth') {
    stage('Docker Push') {
      def image = 'istio-ca'
      def tags = "${env.GIT_SHA}"
      utils.publishDockerImagesToContainerRegistry(images, tags)
    }
  }
}

def stablePostsubmit(gitUtils, bazel, utils) {
  goBuildNode(gitUtils, 'istio.io/auth') {
    bazel.updateBazelRc()
    stage('Docker Push') {
      def date = new Date().format("YYYY-MM-dd-HH.mm.ss")
      def images = 'istio-ca'
      def tags = "${env.GIT_SHORT_SHA},${env.ISTIO_VERSION}-${env.GIT_SHORT_SHA},latest"
      if (env.GIT_TAG != '') {
        if (env.GIT_TAG == env.ISTIO_VERSION) {
          // Retagging
          tags = env.ISTIO_VERSION
        } else {
          tags += ",${env.GIT_TAG}"
        }
      }
      utils.publishDockerImagesToDockerHub(images, tags)
      utils.publishDockerImagesToContainerRegistry(images, tags, '', 'gcr.io/istio-io')
    }
  }
}