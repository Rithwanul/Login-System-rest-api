<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use App\Notifications\SignupActivate;
use Illuminate\Support\Str;
use Avatar;


// import the Avatar class

use Illuminate\Support\Facades\Storage;

class AuthController extends Controller
{
    /**
     * User Authentication and create token
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [boolean] remember_me
     * @return [string] access_token
     * @return [string] token_type
     * @return [string] expires_at
     */
    public function Login(Request $request){
        $rules = [
            'email'             =>          'required|string|email',
            'password'          =>          'required|string',
            'remember_me'       =>          'boolean'
        ];

        $request->validate($rules);
        $credentials                    =           request(['email', 'password']);
        $credentials['activate']        =           1;
        $credentials['deleted_at']      =           null;

        $result = Auth::attempt($credentials);

        if(!$result){
            return response()->json([
                'message'       =>      'Unauthorized'
            ], 401);
        }

        $user = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');

        $token = $tokenResult->token;

        if($request->remember_me){
            $token->expires_at = Carbon::now()->addWeeks(1);
        }

        $token->save();

        return response()->json([
            'access_token'      => $tokenResult->accessToken,
            'token_type'        => 'Bearer',
            'expires_at'        => Carbon::parse(
                $tokenResult->token->expires_at
            )->toDateTimeString()
        ]);
    }

    /**
     * Create user
     *
     * @param  [string] name
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @return [string] message
     */
    public function SignUp(Request $request){

        $rules = [
            'name'          =>          'required|string|min:4|max:50',
            'email'         =>          'required|email|unique:users',
            'password'      =>          'required|min:6|string|confirmed'
        ];

        $request->validate($rules);

        $user                   =           new User();
        $user->name             =           $request->name;
        $user->email            =           $request->email;
        $user->password         =           bcrypt($request->password);
        $user->activation_token =           Str::random(60);
        $user->save();

        $avatar = Avatar::create($user->name)->getImageObject()->encode('png');
        Storage::put('avatars/'.$user->id.'/avatar.png', (string) $avatar);

        $mail = new SignupActivate($user);
        $user->notify($mail);
        return response()->json([
            'message'   =>  'User created Successfully'
        ], 201);

    }

    /**
     * Logout user (Revoke the token)
     *
     * @return [string] message
     */
    public function Logout(Request $request){
        $request->user()->token()->revoke();

        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }

    /**
     * Get the authenticated User
     *
     * @return [json] user object
     */
    public function User(Request $request){
        return response()->json($request->user());
    }

    /**
     * Activate account for register users
     *
     * @param [string] token
     * @return [json] user object
     */
    public function SignUpActivate($token){
        $user = User::where('activation_token', $token)->first();

        if(!$user){
            return response()->json([
                'message'       =>      'This activation token is invalid.'
            ], 404);
        }

        $user->activate             =               true;
        $user->activation_token     =               '';
        $user->save();

        return $user;
    }
}
