<?php
    require_once 'config.php';

    class DataBase{

        private $hostname = DB_HOST;
        private $database = DB_NAME;
        private $username = DB_USER;
        private $password = DB_PASS;
        private $charset = "utf8";

        function conectar(){

            try{

            $conextion = "mysql:host=" . $this->hostname . "; dbname=" . $this->database . "; charset=" . $this->charset;

            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_LOCAL_INFILE => true
            ];

            $pdo = new PDO($conextion, $this->username, $this->password, $options);

            return $pdo;

            } catch(PDOException $e) {

                echo 'Error de conexión: ' . $e->getMessage();
                exit;
            }
        }
    }


?>
