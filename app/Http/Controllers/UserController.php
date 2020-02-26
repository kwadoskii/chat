<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $username = $request->username;
        $password = $request->password;

        if ($this->checkIfUserExist($username)) {
            return response()->json([
                'message' => 'User already exists'
            ], 500);
        } else {
            $password = bcrypt($password);
            User::create([
                'username' => $username,
                'password' => $password
            ]);
            return response()->json(true);
        }
    }

    public function login(Request $request)
    {
        $username = $request->username;
        $password = $request->password;

        $user = $this->checkIfUserExist($username);

        if($user){
            $confirmPassword = Hash::check($password, $user->password);

            return response()->json([
                'status' => $confirmPassword,
                'token' => $user->authToken
            ]);
        } else {
            return response()->json([
                'message' => 'Invalid credentials'
            ], 500);
        }
    }

    public function updateToken(Request $request)
    {
        $username = $request->uid;
        $token = $request->token;

        User::where('username', $username)->update([
            'authToken' => $token
        ]);
    }

    private function checkIfUserExist($username)
    {
        $user = User::where('username', $username)->first();
        if ($user) {
            return $user;
        } else {
            return false;
        }
    }
}
