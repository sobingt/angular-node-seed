angular.module('MyApp', ['ngResource', 'ngMessages', 'ui.router', 'mgcrea.ngStrap', 'satellizer'])
  .config(function($stateProvider, $urlRouterProvider, $authProvider) {
    $stateProvider
      .state('home', {
        url: '/',
        templateUrl: 'partials/home.html'
      })
      .state('login', {
        url: '/login',
        templateUrl: 'partials/login.html',
        controller: 'LoginCtrl'
      })
      .state('signup', {
        url: '/signup',
        templateUrl: 'partials/signup.html',
        controller: 'SignupCtrl'
      })
      .state('logout', {
        url: '/logout',
        template: null,
        controller: 'LogoutCtrl'
      })
      .state('profile', {
        url: '/profile',
        templateUrl: 'partials/profile.html',
        controller: 'ProfileCtrl',
        resolve: {
          authenticated: function($q, $location, $auth) {
            var deferred = $q.defer();

            if (!$auth.isAuthenticated()) {
              $location.path('/login');
            } else {
              deferred.resolve();
            }

            return deferred.promise;
          }
        }
      });

    $urlRouterProvider.otherwise('/');

    $authProvider.facebook({
      clientId: '631388166902710'
    });

    $authProvider.google({
      clientId: '566588809382-t7g6gmdik8q6g7mtk5apqmfqs4uiu37j.apps.googleusercontent.com'
    });

    $authProvider.github({
      clientId: '506f66d607e44defbe0e'
    });

    $authProvider.linkedin({
      clientId: '75ituwm22trpn1',
      scope: ['r_emailaddress']
    });

    $authProvider.twitter({
      url: '/auth/twitter'
    });

  });
