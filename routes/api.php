<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Auth\PasswordResetController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:api')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::group(['prefix' => 'auth'], function () {
    Route::post('login', [AuthController::class, 'Login']);
    Route::post('signup', [AuthController::class, 'SignUp']);
    Route::get('signup/activate/{token}', [AuthController::class, 'SignUpActivate']);

    Route::group(['middleware' => 'auth:api'], function () {
        Route::get('logout', [AuthController::class, 'Logout']);
        Route::get('user', [AuthController::class, 'User']);
    });
});

Route::group([
    'prefix'        =>       'password',
    'namespace'     =>       'Auth',
    'middleware'    =>       'api'
], function () {
    Route::post('create', [PasswordResetController::class, 'Create']);
    Route::get('find/{token}', [PasswordResetController::class, 'Find']);
    Route::post('reset', [PasswordResetController::class, 'Reset']);
});
