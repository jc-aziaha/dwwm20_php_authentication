<?php

    /**
     * Vérifie si l'email envoyé par l'utilisateur existe dèjà ou non.
     *
     * @param string $email
     * @param PDO $db
     * 
     * @return boolean retourne true si l'email existe et false dans le cas contraire.
     */
    function already_exists(string $email, PDO $db): bool
    {
        // Vérifier si l'email correspond à celui d'un utilisateur existant dans la base de données.
        $request = $db->prepare("SELECT id FROM user WHERE email=:email");
        $request->bindValue(":email", $email);
        $request->execute();

        // Si c'est le cas,
        if ( $request->rowCount() == 1 ) 
        {
            // la fonction retourne true
            return true;
        }
        
        // Dans le cas contraire,
        // la fonction retourne false
        return false;
    }


    /**
     * Récupère l'utilisateur connecté
     *
     * @param PDO $db
     * @return array|null
     */
    function getUser(PDO $db): array|null
    {
        if ( !isset($_SESSION['auth']) || empty($_SESSION['auth']) ) 
        {
            return null;
        }

        $request = $db->prepare("SELECT * FROM user WHERE id=:id");
        $request->bindValue(":id", $_SESSION['auth']['id']);
        $request->execute();

        if ($request->rowCount() != 1) 
        {
            return null;
        }
        
        return $request->fetch();
    }