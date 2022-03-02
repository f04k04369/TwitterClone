<?php
///////////////////////
///サインアップコントローラー
///////////////////////

//設定関連を読み込む
include_once '../config.php';
//便利な関数を読み込む
include_once '../util.php';
//ユーザーデータ操作モデルを読み込み
include_once '../Models/users.php';


//登録項目が全て入力されていれば
if(isset($_POST['nickname']) && isset($_POST['name']) && isset($_POST['email']) && isset($_POST['password'])){
    $data = [
        'nickname' =>$_POST['nickname'],
        'name' =>$_POST['name'],
        'email' =>$_POST['email'],
        'password' =>$_POST['password']
    ];

    // ---------------
    // バリデーション
    // --------------
    // 文字数制限（全ての入力項目に対して行う）
    $length = mb_strlen($data['nickname']);
    if ($length < 1 || $length > 50) {
        $error_messages[] = 'ニックネームは1〜50文字にしてください';
    }
    // メールアドレス
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        $error_messages[] = 'メールアドレスが不正です';
    }
    //ユーザーを作成し、成功すれば
    if(createUser($data)){
        //ログイン画面に遷移
        header('Location: ' . HOME_URL .'Controllers/sign-in.php');
    }
}
//画面表示
include_once '../Views/sign-up.php';
?>