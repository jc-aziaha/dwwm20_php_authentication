<?php
session_start();

    require __DIR__ . "/../functions/dbConnector.php";
    require __DIR__ . "/../functions/authenticator.php";

    $db = connectToDb();

    if (!getUser($db)) 
    {
        return header("Location: index.php");
    }

    // Si les données arrivent au serveur via la méthode POST
    if ( $_SERVER['REQUEST_METHOD'] === "POST" ) 
    {

        /**
         * *********************************************
         * Traitement des données du formulaire
         * *********************************************
         */

        // 1. Protéger le serveur contre les failles de type csrf
        if ( !array_key_exists('csrf_token', $_POST) ) 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données
            // Arrêter l'exécution du script.
            return header("Location: register.php");
        }
        
        if ( !isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) ) 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données
            // Arrêter l'exécution du script.
            return header("Location: register.php");
        }

        if ( empty($_POST['csrf_token']) || empty($_SESSION['csrf_token']) ) 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données
            // Arrêter l'exécution du script.
            return header("Location: register.php");
        }

        if ( $_POST['csrf_token'] !== $_SESSION['csrf_token'] ) 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données
            // Arrêter l'exécution du script.
            return header("Location: register.php");
        }


        // 2. Protéger le serveur contre les robots spameurs
        if ( ! array_key_exists('honey_pot', $_POST) ) 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données
            // Arrêter l'exécution du script.
            return header("Location: register.php");
        }

        if ($_POST['honey_pot'] !== "") 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données
            // Arrêter l'exécution du script.
            return header("Location: register.php");
        }


        // 3. Définir les contraintes de validation
        $formErrors = [];

        if ( isset($_POST['firstName']) ) 
        {
            if ( trim($_POST['firstName']) == "" ) 
            {
                $formErrors['firstName'] = "Le prénom est obligatoire.";
            }
            else if( mb_strlen($_POST['firstName']) > 255 )
            {
                $formErrors['firstName'] = "Le prénom ne doit pas dépasser 255 caractères.";
            }
            else if( !preg_match("/^[0-9A-Za-zÀ-ÖØ-öø-ÿ' _-]+$/u", $_POST['firstName']) )
            {
                $formErrors['firstName'] = "Le prénom ne peut contenir que des chiffres, des lettres, le tiret du mieu et l'undescore.";
            }
        }  

        if ( isset($_POST['lastName']) ) 
        {
            if ( trim($_POST['lastName']) == "" ) 
            {
                $formErrors['lastName'] = "Le nom est obligatoire.";
            }
            else if( mb_strlen($_POST['lastName']) > 255 )
            {
                $formErrors['lastName'] = "Le nom ne doit pas dépasser 255 caractères.";
            }
            else if( !preg_match("/^[0-9A-Za-zÀ-ÖØ-öø-ÿ' _-]+$/u", $_POST['lastName']) )
            {
                $formErrors['lastName'] = "Le nom ne peut contenir que des chiffres, des lettres, le tiret du mieu et l'undescore.";
            }
        }  

        if ( isset($_POST['email']) ) 
        {
            if ( trim($_POST['email']) == "" ) 
            {
                $formErrors['email'] = "L'email est obligatoire.";
            }
            else if( mb_strlen($_POST['email']) > 255 )
            {
                $formErrors['email'] = "L'email ne doit pas dépasser 255 caractères.";
            }
            else if( !filter_var($_POST['email'], FILTER_VALIDATE_EMAIL) ) // Permet de valider le format de l'email
            {
                $formErrors['email'] = "Le format de l'email est invalide.";
            }
            else if ( already_exists($_POST['email'], $db) )
            {
                $formErrors['email'] = "Impossible de créer un compte avec cet email.";
            }
        }

        if ( isset($_POST['password']) )
        {
            if ( trim($_POST['password']) == "" ) 
            {
                $formErrors['password'] = "Le mot de passe est obligatoire.";
            }
            else if( mb_strlen($_POST['password']) < 12 || mb_strlen($_POST['password']) > 255 )
            {
                $formErrors['password'] = "Le mot de passe doit avoir au minimum 12 caractères.";
            }
            else if( !preg_match("/^(?=.*[a-zà-ÿ])(?=.*[A-ZÀ-Ỳ])(?=.*[0-9])(?=.*[^a-zà-ÿA-ZÀ-Ỳ0-9]).{11,255}$/", $_POST['password']) )
            {
                $formErrors['password'] = "Le mot de passe doit contenir au moins un chiffre, une lettre minuscule, une lettre majuscule et un caractère spéciale.";
            }
        }


        if ( isset($_POST['confirmPassword']) )
        {
            if ( trim($_POST['confirmPassword']) == "" ) 
            {
                $formErrors['confirmPassword'] = "La confirmation du mot de passe est obligatoire.";
            }
            else if( mb_strlen($_POST['confirmPassword']) < 12 || mb_strlen($_POST['confirmPassword']) > 255 )
            {
                $formErrors['confirmPassword'] = "La confirmation du mot de passe doit contenir au minimum 12 caractères.";
            }
            else if( !preg_match("/^(?=.*[a-zà-ÿ])(?=.*[A-ZÀ-Ỳ])(?=.*[0-9])(?=.*[^a-zà-ÿA-ZÀ-Ỳ0-9]).{11,255}$/", $_POST['confirmPassword']) )
            {
                $formErrors['password'] = "Le mot de passe doit contenir au moins un chiffre, une lettre minuscule, une lettre majuscule et un caractère spéciale.";
            }
            else if( $_POST['password'] !== $_POST['confirmPassword'] )
            {
                $formErrors['confirmPassword'] = "Le mot de passe doit être identique à sa confirmation.";
            }
        }

        // 4. Si le formulaire est soumis mais non valide
        if ( count($formErrors) > 0 ) 
        {

            $_SESSION['formErrors'] = $formErrors;

            $_SESSION['old'] = $_POST;

            // Effectuer une redirection vers la page de laquelle proviennent les données
            // Arrêter l'exécution du script.
            return header("Location: register.php");
        }

        // var_dump("Continuer la partie"); die();
        $passwordHashed = password_hash($_POST['password'], PASSWORD_BCRYPT);

        // Dans le contraire
        // 6. Effectuer la requête du nouvel utilisateur en base de données.
        $request = $db->prepare("INSERT INTO user (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, now(), now() ) ");

        $request->bindValue(":first_name", $_POST['firstName']);
        $request->bindValue(":last_name", $_POST['lastName']);
        $request->bindValue(":email", $_POST['email']);
        $request->bindValue(":password", $passwordHashed);

        $request->execute();
        $request->closeCursor();

        // 7. Générer le message flash de succès
        $_SESSION['success'] = "Votre compte a bien été créé; Vous pouvez vous connecter";

        // 8. Rediriger l'utilisateur vers la page de connexion
            // Arrêter l'exécution du script.
        return header("Location: login.php");
    }

    // Générons notre jéton de sécurité pour la clé csrf.
    $_SESSION['csrf_token'] = bin2hex(random_bytes(10));
?>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Document</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    </head>
    <body class="bg-light">

        <!-- Main -->
        <main>
            <div class="container my-5">
                <div class="row">
                    <div class="col-md-6">
                        <h1 class="text-center my-3 display-5">Inscription</h1>

                        <?php if(isset($_SESSION['formErrors']) && !empty($_SESSION['formErrors'])) : ?>
                            <div class="alert alert-danger" role="alert">
                                <ul>
                                    <?php foreach($_SESSION['formErrors'] as $error) : ?>
                                        <li><?= $error ?></li>
                                    <?php endforeach ?>
                                </ul>
                            </div>
                            <?php unset($_SESSION['formErrors']); ?>
                        <?php endif ?>
            
                        <!-- Form -->
                        <form method="post">
                            <div class="mb-3">
                                <input type="text" name="firstName" placeholder="Votre prénom" class="form-control" autofocus value="<?= isset($_SESSION['old']['firstName']) && !empty(isset($_SESSION['old']['firstName'])) ? htmlspecialchars($_SESSION['old']['firstName']) : ''; unset($_SESSION['old']['firstName']); ?>">
                            </div>
                            <div class="mb-3">
                                <input type="text" name="lastName" placeholder="Votre nom" class="form-control" value="<?= isset($_SESSION['old']['lastName']) && !empty(isset($_SESSION['old']['lastName'])) ? htmlspecialchars($_SESSION['old']['lastName']) : ''; unset($_SESSION['old']['lastName']); ?>">
                            </div>
                            <div class="mb-3">
                                <input type="email" name="email" placeholder="Votre email" class="form-control" value="<?= isset($_SESSION['old']['email']) && !empty(isset($_SESSION['old']['email'])) ? htmlspecialchars($_SESSION['old']['email']) : ''; unset($_SESSION['old']['email']); ?>">
                            </div>
                            <div class="mb-3">
                                <input type="text" name="password" placeholder="Votre mot de passe" class="form-control" value="<?= isset($_SESSION['old']['password']) && !empty(isset($_SESSION['old']['password'])) ? htmlspecialchars($_SESSION['old']['password']) : ''; unset($_SESSION['old']['password']); ?>">
                            </div>
                            <div class="mb-3">
                                <input type="text" name="confirmPassword" placeholder="Confirmation de votre mot de passe" class="form-control">
                            </div>
                            <div>
                                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                            </div>
                            <div>
                                <input type="hidden" name="honey_pot" value="">
                            </div>
                            <div>
                                <input formnovalidate type="submit" class="btn btn-primary w-100" value="S'inscrire">
                            </div>
                        </form>
            
                        <div class="mt-3 text-center">
                            <p>Vous avez déjà un compte? <a href="/login.php">Connectez-vous</a></p>
                            <a href="/index.php">Revenir à l'accueil</a>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <!-- Image -->
                        <img src="/images/register.png" class="img-fluid" alt="">
                    </div>
                </div>
            </div>
        </main>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
    </body>
</html>