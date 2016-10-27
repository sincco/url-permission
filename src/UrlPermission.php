<?php
# NOTICE OF LICENSE
#
# This source file is subject to the Open Software License (OSL 3.0)
# that is available through the world-wide-web at this URL:
# http://opensource.org/licenses/osl-3.0.php
#
# -----------------------
# @author: Iván Miranda
# @version: 1.0.0
# -----------------------
# Control for valid user data on app
# -----------------------

namespace Sincco\Sfphp;

final class UrlPermission extends \stdClass {
    private static $instance;
    private static $dbData;
    private static $dbConnection;

    /**
     * Sets data base information connection for the instance
     * @param array $data Database connecion ( host, user, password, dbname, type )
     */
    public static function setDatabase( $data ) {
        if(!self::$instance instanceof self)
            self::$instance = new self();
        self::$dbData = $data;
    }


    /**
     * Checks if user is logged
     * @return mixed           FALSE if not logged, user data if logged
     */
    public static function isLogged() {
        if(!self::$instance instanceof self)
            self::$instance = new self();
    // Start a session (if has not been started)
        self::$instance->startSession();
    // If exists user's data in session then is logged
        if( isset( $_SESSION['sincco\login\controller'] ) ) {
            self::$instance->startSession();
            return unserialize( $_SESSION['sincco\login\controller'] );
        }
        else
            return FALSE;
    }

    /**
     * Attemps a user login
     * @param  array $userData User data ( user/email, password)
     * @return mixed           FALSE if not logged, user data if logged
     */
    public static function login( $userData ) {
        if( !self::$instance->verifyTableExists() )
            if ( !self::$instance->createTable() )
                return FALSE;
        $response = self::$instance->getUser($userData['user']);
        if( $response ) {
            $response = array_shift($response);
            if( password_verify( $userData['password'], $response['userPassword'] ) ) {
                $_SESSION['sincco\login\controller'] = serialize( $response );
            } else 
                $response = FALSE;
        }
        return $response;
    }

    /**
     * Creates a new user account
     * @param  array $userData User data (user,email,password)
     * @return boolean
     */
    public static function registerPermission($data) {
        if(!self::$instance instanceof self)
            self::$instance = new self();
        if( !self::$instance->verifyTableExists() )
            if ( !self::$instance->createTable() )
                return FALSE;
        $data['password'] = self::$instance->createPasswordHash( $data['password'] );
        try {
            $sql = 'INSERT INTO __usersControl (userId,userName, userPassword, userEmail)
                VALUES(:user_id, :user_name, :user_password, :user_email)';
            $query = self::$dbConnection->prepare($sql);
            $data = array( ':user_id'=>$id,
                ':user_name'=>$data['user'],
                ':user_email'=>$data['email'],
                ':user_password'=>$data['password'] );
            if ($query->execute( $data )){
                return $id;
            } else {
                return false;
            }
        } catch (\PDOException $err) {
            return FALSE;
        }
    }

    public static function editUser( $userData ) {
        if(!self::$instance instanceof self)
            self::$instance = new self();
        if( !self::$instance->verifyTableExists() )
            if ( !self::$instance->createTable() )
                return FALSE;
        $userData[ 'password' ] = self::$instance->createPasswordHash( $userData[ 'password' ] );
        try {
            if($userData[ 'password' ] == '') {
                $sql = 'UPDATE __usersControl 
                    SET userEmail=\'' . $userData[ 'email' ] . '\'
                    WHERE userName=\'' . $userData[ 'user' ] . '\' OR userEmail=\'' . $userData[ 'user' ] . '\'';
            } else {
                $sql = 'UPDATE __usersControl 
                    SET userPassword=\'' . $userData[ 'password' ] . '\', userEmail=\'' . $userData[ 'email' ] . '\'
                    WHERE userName=\'' . $userData[ 'user' ] . '\' OR userEmail=\'' . $userData[ 'user' ] . '\'';
            }
            $query = self::$dbConnection->prepare($sql);
            return $query->execute();
        } catch (\PDOException $err) {
            return FALSE;
        }
    }

    /**
     * Get user data from database
     * @param  array $user User data (user,email,password)
     * @return array       User Data
     */
    public static function getUser($user) {
        $sql = "SELECT userId, userName, userEmail, userPassword
            FROM __usersControl
            WHERE userName = '{$user}' OR userEmail = '{$user}'
            LIMIT 1";
        $query = self::$dbConnection->prepare($sql);
        $query->execute();
        return $query->fetchAll(\PDO::FETCH_ASSOC);
    }

    /**
     * Create a token for a form to be included in post requests
     * @param  string $form Form Name
     * @return string       Token string
     */
    public static function generateFormToken($form) {
        $token = md5(uniqid(microtime(), TRUE));  
        $_SESSION['sincco\login\controller\form' . $form . '\token'] = $token; 
        return $token;
    }

    /**
     * Gets new user ID
     * @return int User ID autonumeric
     */
    private function nextUserId() {
        $sql = 'SELECT max(userId) FROM __usersControl';
        $query = self::$dbConnection->prepare($sql);
        $query->execute();
        return $query->fetchAll(\PDO::FETCH_ASSOC);
    }

    /**
     * Create a hash for a user password, if password_hash function exists, is used, 
     * otherwise this class implements a custom hash generator
     * @param  string $password Password string for user data
     * @return string           Hash for password
     */
    private function createPasswordHash($password) {
        if( function_exists( 'password_hash' ) ) {
            $opciones = [ 'cost' => 12, ];
            return password_hash($password, PASSWORD_BCRYPT, $opciones);
        }
    }

    /**
     * Checks if user data table exists
     * @return boolean
     */
    private function verifyTableExists() {
        if(!self::$dbConnection instanceof \PDO)
            self::$instance->connectDB();
        $sql = 'SELECT * FROM __groupsPermission LIMIT 1';
        try {
            $query = self::$dbConnection->prepare($sql);
            $query->execute();
            return TRUE;
        } catch (\PDOException $err) {
            return FALSE;
        }
    }

    /**
     * Create the table for user data
     * @return boolean
     */
    private function createTable() {
        if(!self::$dbConnection instanceof \PDO)
            self::$instance->connectDB();
        $sql = 'CREATE TABLE __groupsPermission (
            groupId int not null,
            url varchar(100)
        )';
        try {
            $query = self::$dbConnection->prepare($sql);
            $query->execute();
            return TRUE;
        } catch (\PDOException $err) {
            return FALSE;
        }
    }

    /**
     * Open a new connection with data base
     * @return PDO:Object
     */
    private function connectDB() {
        if(!isset(self::$dbData["charset"]))
            self::$dbData["charset"] = "utf8";
        $parametros = array();
        if(self::$dbData["type"] == "mysql")
            $parametros = array(\PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES '. self::$dbData["charset"]);
        else
            $parametros = array();
        try {
            switch (self::$dbData["type"]) {
                case 'sqlsrv':
                    self::$dbConnection = new \PDO(self::$dbData["type"].":Server=".self::$dbData["host"].";",
                    self::$dbData["user"], self::$dbData['password'], $parametros);
                break;
                case 'mysql':
                    self::$dbConnection = new \PDO(self::$dbData["type"].":host=".self::$dbData["host"].";dbname=".self::$dbData["dbname"],
                    self::$dbData["user"], self::$dbData['password'], $parametros);
                break;
                case 'firebird':
                    $parametros = array(
                    \PDO::FB_ATTR_TIMESTAMP_FORMAT,"%d-%m-%Y",
                    \PDO::FB_ATTR_DATE_FORMAT ,"%d-%m-%Y"
                    );
                    self::$dbConnection = new \PDO(self::$dbData["type"].":dbname=".self::$dbData["host"].self::$dbData["dbname"], self::$dbData["user"], self::$dbData['password'], $parametros);
                break;
                default:
                    self::$dbConnection = new \PDO(self::$dbData["type"].":host=".self::$dbData["host"].";dbname=".self::$dbData["dbname"],
                    self::$dbData["user"], self::$dbData['password']);
                break;
            }
            self::$dbConnection->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            self::$dbConnection->setAttribute(\PDO::ATTR_EMULATE_PREPARES, false);
            return TRUE;
        } catch (\PDOException $err) {
            $errorInfo = sprintf( '%s: %s in %s on line %s.',
                'Database Error',
                $err,
                $err->getFile(),
                $err->getLine()
            );
            return FALSE;
        }
    }

}