(function() {
  var app = angular.module('ECSPortal', ['ngAnimate', 'ngSanitize', 'angularUtils.directives.dirPagination']);

  app.value('loadingService', {
    loadingCount: 0,
    isLoading: function() { return loadingCount > 0; },
    requested: function() { loadingCount += 1; },
    responded: function() { loadingCount -= 1; }
  });

  app.factory('loadingInterceptor', ['$q', 'loadingService', function($q, loadingService) {
    return {
      request: function(config) {
        loadingService.requested();
        return config;
      },
      response: function(response) {
        loadingService.responded();
        console.log(response);
        return response;
      },
      responseError: function(rejection) {
        loadingService.responded();
        return $q.reject(rejection);
      },
    }
  }]);

  app.config(["$httpProvider", function ($httpProvider) {
    $httpProvider.interceptors.push('loadingInterceptor');
  }]);
// Main controller that calls APIs to get the list of buckets and information about ECS
  app.controller('EcsPortalController', ['$http', '$animate', '$scope', 'loadingService', 'ecsportalsService', function($http, $animate, $scope, loadingService, ecsportalsService) {
    $scope.ecsportal = ecsportalsService;
    loadingCount = 0;
    $scope.loadingService = loadingService;
    $scope.ecsportal.buckets = [];
    $scope.ecsportal.hostname = "";
    $scope.ecsportal.ecs = {};
    $scope.information = 0;
    $http.get('/api/v1/buckets').success(function(data) {
      $scope.ecsportal.buckets = data;
    }).
    error(function(data, _status, _headers, _config) {
      $scope.ecsportal.messagetitle = "Error";
      $scope.ecsportal.messagebody = data;
      $('#message').modal('show');
    });
    $http.get('/api/v1/ecs').success(function(data) {
      $scope.ecsportal.ecs = data;
    }).
    error(function(data, _status, _headers, _config) {
      $scope.ecsportal.messagetitle = "Error";
      $scope.ecsportal.messagebody = data;
      $('#message').modal('show');
    });
  }]);  
  
  app.factory('ecsportalsService', function() {
    return {}
  });

  // Crate a new bucket
  app.directive("ecsportalBucket", function() {
    return {
      restrict: 'E',
      templateUrl: "app/components/ecsportal-bucket.html",
      controller: ['$http', '$scope', 'ecsportalsService', function($http, $scope, ecsportalsService) {
        $scope.ecsportal = ecsportalsService;
        this.createBucket = function() {
          $http.post('/api/v1/createbucket', {bucket: this.bucket, encrypted: false}).
            success(function(data, _status, _headers, _config) {
              $scope.ecsportal.buckets.push(data["bucket"]);
              $scope.ecsportal.messagetitle = "Success";
              $scope.ecsportal.messagebody = "Bucket created with the following CORS configuration:<br /><br /><pre class='prettyprint'><code class='language-xml'>" + data["cors_configuration"].encodeHTML() + "</pre></code>";
              $('#message').modal({show: true});
            }).
            error(function(data, status, headers, config) {
              $scope.ecsportal.messagetitle = "Error";
              $scope.ecsportal.messagebody = data;
              $('#message').modal({show: true});
            });
        };
      }],
      controllerAs: "bucketController"
    };
  });
});