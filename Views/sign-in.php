<!DOCTYPE html>
<html lang="ja">

<head>
    <?php include_once('../Views/common/head.php');?>
<!--タイトル表示-->
    <title>ログイン / Twitterクローン</title>
    <meta name="description" content="ログインです">
</head>
<body class="signup text-center">
    <main class="form-signup">
        <form action="sign-in.php" method="post">
            <img src="<?php echo HOME_URL;?>Views/img/logo-white.svg" alt="" class="logo-white">
            <h1>Twitterクローンにログイン</h1>

            <?php if (isset($view_try_login_result) && $view_try_login_result === false): ?>
                <div class="alert alert-warning text-sm" role="alert">
                    ログインに失敗しました。メールアドレス、パスワードが正しいかご確認ください。
                </div>
            <?php endif; ?>

            <input type="email" class="form-control" name="email" placeholder="メールアドレス" required autofocus >
            <input type="password" class="form-control" name="password" placeholder="パスワード" required>
            <button class="w-100 btn btn-lg" type="submit">ログイン</button>
            <p class="mt-3 mb-2"><a href="sign-up.php">会員登録する</a></p>
            <p class="mt-2 mt-3 text-muted">&copy; 2021</p>
        </form>
    </main>
    <?php include_once('../Views/common/foot.php'); ?>
</body>
</html>