﻿angular
    .module('bit.vault')

    .controller('vaultEditCipherController', function ($scope, apiService, $uibModalInstance, cryptoService, cipherService,
        passwordService, cipherId, $analytics, $rootScope, authService, $uibModal, constants, $filter) {
        $analytics.eventTrack('vaultEditCipherController', { category: 'Modal' });
        $scope.folders = $rootScope.vaultFolders;
        $scope.cipher = {};
        $scope.readOnly = false;
        $scope.constants = constants;

        authService.getUserProfile().then(function (profile) {
            $scope.useTotp = profile.premium;
            return apiService.ciphers.get({ id: cipherId }).$promise;
        }).then(function (cipher) {
            $scope.cipher = cipherService.decryptCipher(cipher);
            $scope.readOnly = !$scope.cipher.edit;
            $scope.useTotp = $scope.useTotp || $scope.cipher.organizationUseTotp;
            setUriMatchValues();
        });

        $scope.save = function (model) {
            if ($scope.readOnly) {
                $scope.savePromise = apiService.ciphers.putPartial({ id: cipherId }, {
                    folderId: model.folderId,
                    favorite: model.favorite
                }, function (response) {
                    $analytics.eventTrack('Partially Edited Cipher');
                    $uibModalInstance.close({
                        action: 'partialEdit',
                        data: {
                            id: cipherId,
                            favorite: model.favorite,
                            folderId: model.folderId && model.folderId !== '' ? model.folderId : null
                        }
                    });
                }).$promise;
            }
            else {
                var cipher = cipherService.encryptCipher(model, $scope.cipher.type);
                $scope.savePromise = apiService.ciphers.put({ id: cipherId }, cipher, function (cipherResponse) {
                    $analytics.eventTrack('Edited Cipher');
                    var decCipher = cipherService.decryptCipherPreview(cipherResponse);
                    $uibModalInstance.close({
                        action: 'edit',
                        data: decCipher
                    });
                }).$promise;
            }
        };

        $scope.generatePassword = function () {
            if (!$scope.cipher.login.password || confirm('Are you sure you want to overwrite the current password?')) {
                $analytics.eventTrack('Generated Password From Edit');
                $scope.cipher.login.password = passwordService.generatePassword({ length: 14, special: true });
            }
        };

        $scope.addUri = function () {
            if (!$scope.cipher.login) {
                return;
            }

            if (!$scope.cipher.login.uris) {
                $scope.cipher.login.uris = [];
            }

            $scope.cipher.login.uris.push({
                uri: null,
                match: null,
                matchValue: null
            });
        };

        $scope.removeUri = function (uri) {
            if (!$scope.cipher.login || !$scope.cipher.login.uris) {
                return;
            }

            var index = $scope.cipher.login.uris.indexOf(uri);
            if (index > -1) {
                $scope.cipher.login.uris.splice(index, 1);
            }
        };

        $scope.uriMatchChanged = function (uri) {
            if ((!uri.matchValue && uri.matchValue !== 0) || uri.matchValue === '') {
                uri.match = null;
            }
            else {
                uri.match = parseInt(uri.matchValue);
            }
        };

        $scope.addField = function () {
            if (!$scope.cipher.fields) {
                $scope.cipher.fields = [];
            }

            $scope.cipher.fields.push({
                type: constants.fieldType.text.toString(),
                name: null,
                value: null
            });
        };

        $scope.removeField = function (field) {
            var index = $scope.cipher.fields.indexOf(field);
            if (index > -1) {
                $scope.cipher.fields.splice(index, 1);
            }
        };

        $scope.toggleFavorite = function () {
            $scope.cipher.favorite = !$scope.cipher.favorite;
        };

        $scope.clipboardSuccess = function (e) {
            e.clearSelection();
            selectPassword(e);
        };

        $scope.clipboardError = function (e, password) {
            if (password) {
                selectPassword(e);
            }
            alert('Your web browser does not support easy clipboard copying. Copy it manually instead.');
        };

        $scope.folderSort = function (item) {
            if (!item.id) {
                return '';
            }

            return item.name.toLowerCase();
        };

        function selectPassword(e) {
            var target = $(e.trigger).parent().prev();
            if (target.attr('type') === 'text') {
                target.select();
            }
        }

        $scope.delete = function () {
            if (!confirm('Are you sure you want to delete this item (' + $scope.cipher.name + ')?')) {
                return;
            }

            apiService.ciphers.del({ id: $scope.cipher.id }, function () {
                $analytics.eventTrack('Deleted Cipher From Edit');
                $uibModalInstance.close({
                    action: 'delete',
                    data: $scope.cipher.id
                });
            });
        };

        $scope.close = function () {
            $uibModalInstance.dismiss('cancel');
        };

        $scope.showUpgrade = function () {
            $uibModal.open({
                animation: true,
                templateUrl: 'app/views/premiumRequired.html',
                controller: 'premiumRequiredController'
            });
        };

        function setUriMatchValues() {
            if ($scope.cipher.login && $scope.cipher.login.uris) {
                for (var i = 0; i < $scope.cipher.login.uris.length; i++) {
                    $scope.cipher.login.uris[i].matchValue =
                        $scope.cipher.login.uris[i].match || $scope.cipher.login.uris[i].match === 0 ?
                            $scope.cipher.login.uris[i].match.toString() : '';
                }
            }
        }
    });
