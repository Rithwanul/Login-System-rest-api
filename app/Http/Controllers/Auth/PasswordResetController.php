<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use App\Models\PasswordReset;
use App\Notifications\PasswordResetRequest;
use App\Notifications\PasswordResetSuccess;
use Illuminate\Support\Str;
use Carbon\Carbon;


/**
 * @Author      T.M. Rithwanul Islam
 * @Company
 *
 * Password reset controller contains
 * methods to handle password request
 *
 */


class PasswordResetController extends Controller
{

    /**
     * Create token password reset
     *
     * @param  [string] email
     * @return [string] message
     */
    public function Create(Request $request)
    {
        $rule = [
            'email'         =>          'required|string|email'
        ];

        $request->validate($rule);

        $user = User::where('email', $request->email)->first();

        if(!$user){
            return response()->json([
                'message'   =>      'We did not find any user with this name'
            ], 404);
        }

        $passwordReset = PasswordReset::updateOrCreate(
            [
                'email'    =>      $user->email
            ],
            [
                'email'    =>      $user->email,
                'token'    =>      Str::random(60)
            ]
        );

        if($user && $passwordReset){
            $user->notify(
                new PasswordResetRequest($passwordReset->token)
            );
        }

        return response()->json([
            'message'       =>      'We have e-mailed your password reset link!'
        ]);

    }

    /**
     * Find token password reset
     *
     * @param  [string] $token
     * @return [string] message
     * @return [json] passwordReset object
     */
    public function Find($token)
    {
        $passwordReset = PasswordReset::where('token', $token)->first();

        if(!$passwordReset){
            return response()->json([
                'message' => 'This password reset token is invalid'
            ], 404);
        }

        if(Carbon::parse($passwordReset->updated_at)->addMinutes(720)->isPast()){
            $passwordReset->delete();

            return response()->json([
                'message'       =>          'This password reset token is invalid'
            ], 404);
        }

        return response()->json($passwordReset);
    }

    /**
     * Reset password
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @param  [string] token
     * @return [string] message
     * @return [json] user object
     */
    public function Reset(Request $request)
    {
        $rules = [
            'email'         =>          'required|string|email',
            'password'      =>          'required|string|confirmed',
            'token'         =>          'required|string'
        ];

        $request->validate($rules);

        $passwordReset = PasswordReset::where([
            [
                'email'         ,          $request->email
            ],
            [
                'token'         ,          $request->token
            ]
        ])->first();


        if(!$passwordReset){
            return response()->json([
                'message'           =>              'This token is invalid'
            ], 404);
        }

        $user = User::where('email', $passwordReset->email)->first();

        if(!$user){
            return response()->json([
                'message'           =>              'Invalid user email'
            ], 404);
        }

        $user->password     =       bcrypt($request->password);
        $user->save();

        $passwordReset->delete();

        $user->notify(
            new PasswordResetSuccess($passwordReset)
        );

        return response()->json([
            'message'       =>          'password updated successfully'
        ], 200);
    }
}
