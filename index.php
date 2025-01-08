<?php


ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once 'database.php';
require_once 'config.php';
require_once 'vendor/autoload.php';
require_once 'functions.php';

$db = new DataBase();
$con = $db->conectar();

$dominiosPermitidos = ["http://localhost:5173", "https://luz-interior.free.nf/"];

if (isset($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], $dominiosPermitidos)) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header("Access-Control-Allow-Credentials: true");
}

header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Access-Control-Allow-Methods: OPTIONS, GET, POST, PUT, DELETE");
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Max-Age: 1728000');
    header('Content-Length: 0');
    header('Content-Type: text/plain');
    die();
}

if (!function_exists('getallheaders')) {
    function getallheaders()
    {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headerName = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                $headers[$headerName] = $value;
            }
        }
        return $headers;
    }
}

if (isset($_GET['action'])) {
    $action = $_GET['action'];
    switch ($action) {
        case 'verify-token': //data
            try {
                $authHeader = getallheaders();
                list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
        
                if (empty($jwt)) {
                    throw new Exception("Token ausente");
                }
        
                $decoded = verificarToken($jwt);
        
                if ($decoded) {
                    enviarRespuesta(['success' => true, 'message' => 'Token válido', 'data' => $decoded]);
                } else {
                    throw new Exception("Token inválido o expirado");
                }
            } catch (Exception $e) {
                enviarRespuesta(['success' => false, 'message' => $e->getMessage()]);
            }
            break;

        case 'products':
            $sql = $con->prepare("
                    SELECT
                        products.*,
                         products_images.id_img,
                        products_images.img_url,
                        products_images.priority
                    FROM
                        products
                    LEFT JOIN
                        products_images
                    ON
                        products.id = products_images.product_id
                    ORDER BY
                        products.id, products_images.priority ASC
                ");

            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);

            // Agrupar las imágenes por producto
            $productos = [];
            foreach ($resultado as $row) {
                $id_producto = $row['id'];
                if (!isset($productos[$id_producto])) {
                    // Agregar los datos del producto
                    $productos[$id_producto] = [
                        'id' => $row['id'],
                        'name' => $row['name'],
                        'category' => $row['category'],
                        'price' => $row['price'],
                        'description' => $row['description'],
                        'img_url' => [],
                    ];
                }

                // Agregar la imagen al arreglo del producto
                if ($row['img_url']) {
                    $productos[$id_producto]['img_url'][] = [
                        'id_img' => $row['id_img'],
                        'url' => $row['img_url'],
                        'priority' => $row['priority'],
                    ];
                }
            }

            // Convertir a un arreglo indexado
            $productos = array_values($productos);

            enviarRespuesta($productos);
            break;

        case 'users':
            $sql = $con->prepare("
                SELECT users.*, addresses.*
                FROM users
                LEFT JOIN addresses ON users.id = addresses.id_user
            ");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);

            $usuarios = [];
            foreach ($resultado as $row) {

                if (!isset($usuarios[$row['id']])) {
                    $usuarios[$row['id']] = [
                        'id' => $row['id'],
                        'name' => $row['name'],
                        'email' => $row['email'],
                        'cuit' => $row['cuit'],
                        'approved' => $row['approved'],
                        'role' => $row['role'],
                        'register_date' => $row['register_date'],
                        'new' => $row['new'],
                        'addresses' => []
                    ];
                }

                if ($row['id_address']) {
                    $usuarios[$row['id']]['addresses'][] = [
                        'id' => $row['id_address'],
                        'name' => $row['name'],
                        'last_name' => $row['last_name'],
                        'company_name' => $row['company_name'],
                        'street' => $row['street'],
                        'street2' => $row['street2'],
                        'city' => $row['city'],
                        'province' => $row['province'],
                        'cp' => $row['cp'],
                        'tel' => $row['tel'],
                        'default_address' => $row['default_address']
                    ];
                }
            }

            enviarRespuesta(array_values($usuarios));
            break;
        case 'orders':
            $sql = $con->prepare("
                SELECT orders.*, order_products.*
                FROM orders
                LEFT JOIN order_products ON orders.id_order = order_products.order_id
            ");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);

            $ordenes = [];
            foreach ($resultado as $row) {

                if (!isset($ordenes[$row['id_order']])) {
                    $ordenes[$row['id_order']] = [
                        'id_order' => $row['id_order'],
                        'id_user' => $row['id_user'],
                        'date' => $row['date'],
                        'total_price' => $row['total_price'],
                        'shipping_address' => $row['shipping_address'],
                        'shipping_type' => $row['shipping_type'],
                        'state' => $row['state'],
                        'new' => $row['new'],
                        'products' => []
                    ];
                }

                if ($row['order_id']) {
                    $ordenes[$row['order_id']]['products'][] = [
                        'id' => $row['id'],
                        'product_id' => $row['product_id'],
                        'quantity' => $row['quantity']
                    ];
                }
            }

            enviarRespuesta(array_values($ordenes));
            break;
        case 'company_info':
            $sql = $con->prepare("SELECT * FROM company_info");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);
            enviarRespuesta($resultado);
            echo $resultado;
            break;
        case 'social':
            $sql = $con->prepare("SELECT * FROM social_networks");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);
            enviarRespuesta($resultado);
            echo $resultado;
            break;
        case 'shipping':
            $sql = $con->prepare("SELECT * FROM shipping");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);
            enviarRespuesta($resultado);
            echo $resultado;
            break;
        case 'gallery':
            $sql = $con->prepare("SELECT * FROM gallery_images");
            $sql->execute();
            $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);
            enviarRespuesta($resultado);
            echo $resultado;
            break;
        case 'user-data':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['email'])) {
                    $email = $data['email'];

                    $sql = $con->prepare("
                            SELECT users.*, addresses.*
                            FROM users
                            LEFT JOIN addresses ON users.id = addresses.id_user
                            WHERE users.email = :email
                        ");

                    $sql->bindParam(':email', $email, PDO::PARAM_INT);
                    $sql->execute();
                    $resultado = $sql->fetchAll(PDO::FETCH_ASSOC);

                    $usuario = null;
                    if (!empty($resultado)) {
                        $usuario = [
                            'id' => $resultado[0]['id'],
                            'name' => $resultado[0]['name'],
                            'email' => $resultado[0]['email'],
                            'password' => $resultado[0]['password'],
                            'cuit' => $resultado[0]['cuit'],
                            'tel' => $resultado[0]['tel'],
                            'addresses' => [],
                            'role' => $resultado[0]['role']
                        ];
                        foreach ($resultado as $row) {
                            if ($row['id_address']) {
                                $usuario['addresses'][] = [
                                    'id_address' => $row['id_address'],
                                    'street' => $row['street'],
                                    'street2' => $row['street2'],
                                    'city' => $row['city'],
                                    'province' => $row['province'],
                                    'cp' => $row['cp'],
                                    'name_address' => $row['name_address'],
                                    'last_name' => $row['last_name'],
                                    'company_name' => $row['company_name'],
                                    'tel_address' => $row['tel_address'],
                                    'default_address' => $row['default_address'],
                                ];
                            }
                        }
                    }
                    enviarRespuesta(['success' => true, 'user' => $usuario]);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'ID de usuario no encontrado en el token']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'register-user': // Acciones de usuario
            $data = json_decode(file_get_contents("php://input"), true);

            if (isset($data['data']['name'], $data['data']['cuit'], $data['data']['email'], $data['data']['tel'], $data['data']['password'])) {
                $name = $data['data']['name'];
                $cuit = $data['data']['cuit'];
                $email = $data['data']['email'];
                $tel = $data['data']['tel'];
                $password = password_hash($data['data']['password'], PASSWORD_BCRYPT);
                $approved = false;
                $register_date = $data['date'];

                try {
                    $sql = $con->prepare("INSERT INTO users (name, cuit, email, password, approved, register_date) VALUES (?,?, ?, ?, ?, ?)");
                    $sql->execute([$name, $cuit, $email, $password, $approved, $register_date]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'Usuario registrado exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo registrar el usuario']);
                    }
                } catch (PDOException $e) {
                    if ($e->getCode() == 23000) {
                        enviarRespuesta(['success' => false, 'message' => 'Este usuario ya está registrado']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
            }
            break;

        case 'login':
            $data = json_decode(file_get_contents("php://input"), true);

            $email = $data['email'];
            $password = $data['password'];

            $sql = $con->prepare("SELECT id, password, approved, role FROM users WHERE email = ?");
            $sql->execute([$email]);

            if ($sql->rowCount() > 0) {
                $user = $sql->fetch(PDO::FETCH_ASSOC);
                $userId = $user['id'];
                $hashedPassword = $user['password'];
                $isApproved = $user['approved'];
                $role = $user['role'];

                if ($isApproved) {
                    if (password_verify($password, $hashedPassword)) {
                        $token = generarToken($userId);
                        enviarRespuesta([
                            'success' => true,
                            'message' => 'Inicio de sesión exitoso',
                            'token' => $token,
                            'role' => $role
                        ]);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'Contraseña incorrecta']);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'El usuario no está aprobado']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'El usuario no existe']);
            }
            break;

        case 'recover':
            $data = json_decode(file_get_contents("php://input"), true);
            $email = $data['email'];

            $sql = $con->prepare("SELECT id FROM users WHERE email = ?");
            $sql->execute([$email]);

            if ($sql->rowCount() > 0) {
                $user = $sql->fetch(PDO::FETCH_ASSOC);

                // Generar token y guardarlo en la base de datos
                $token = password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT);
                $expiration = date("Y-m-d H:i:s", strtotime("+1 hour")); // 1 hora de validez

                $insertToken = $con->prepare("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)");
                $insertToken->execute([$user['id'], $token, $expiration]);

                // Enviar correo con el enlace
                $url = "http://localhost:5173/restablecer-contraseña?token=$token";
                $mensaje = "
                        <h1>Recuperar Contraseña</h1>
                        <p>Haz clic en el enlace para restablecer tu contraseña:</p>
                        <a href='$url'>Restablecer Contraseña</a>
                    ";
                if (enviarCorreo($email, "Recuperar Contraseña", $mensaje)) {
                    enviarRespuesta(['success' => true, 'message' => 'Correo de recuperación enviado.']);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'No se pudo enviar el correo. Inténtalo más tarde.']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'El usuario no existe.']);
            }
            break;

        case 'reset-password':
            $data = json_decode(file_get_contents("php://input"), true);
            $token = $data['token'];
            $newPassword = $data['newPassword'];

            // Verificar token en la base de datos
            $sql = $con->prepare("SELECT user_id FROM password_resets WHERE token = ? AND expires_at > NOW()");
            $sql->execute([$token]);

            if ($sql->rowCount() > 0) {
                $user = $sql->fetch(PDO::FETCH_ASSOC);

                $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
                $updatePassword = $con->prepare("UPDATE users SET password = ? WHERE id = ?");
                $updatePassword->execute([$hashedPassword, $user['user_id']]);

                // Eliminar el token usado
                $deleteToken = $con->prepare("DELETE FROM password_resets WHERE token = ?");
                $deleteToken->execute([$token]);

                enviarRespuesta(['success' => true, 'message' => 'Contraseña restablecida correctamente.']);
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado.']);
            }
            break;

        case 'update-personal-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset($data['data']['name'], $data['data']['cuit'], $data['data']['tel'], $data['id'])) {
                    $name = $data['data']['name'];
                    $cuit = $data['data']['cuit'];
                    $tel = $data['data']['tel'];
                    $id = $data['id'];

                    try {
                        $sql = $con->prepare("UPDATE users SET name = :name, cuit = :cuit, tel = :tel WHERE id = :id");
                        $sql->execute([
                            ':name' => $name,
                            ':cuit' => $cuit,
                            ':tel' => $tel,
                            ':id' => $id,
                        ]);

                        if ($sql->rowCount() > 0) {
                            enviarRespuesta(['success' => true, 'message' => 'Información actualizada']);
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la información']);
                        }
                    } catch (PDOException $e) {
                        error_log('Database error: ' . $e->getMessage());
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['status' => 'error', 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'update-account-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset($data['data']['password'], $data['id'])) {
                    $password = password_hash($data['data']['password'], PASSWORD_BCRYPT);
                    $id = $data['id'];

                    try {
                        $sql = $con->prepare("UPDATE users SET password = :password WHERE id = :id");
                        $sql->execute([
                            ':password' => $password,
                            ':id' => $id,
                        ]);

                        if ($sql->rowCount() > 0) {
                            enviarRespuesta(['success' => true, 'message' => 'Información actualizada']);
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la información']);
                        }
                    } catch (PDOException $e) {

                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['status' => 'error', 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'update-address-user':
        case 'add-address-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset(
                    $data['data']['street'],
                    $data['data']['city'],
                    $data['data']['province'],
                    $data['data']['name_address'],
                    $data['data']['last_name'],
                    $data['data']['cp'],
                    $data['data']['tel_address'],
                )) {
                    $userId = $data['id'];
                    $addressData = $data['data'];

                    try {
                        if ($action == 'add-address-user') {

                            if ($addressData['default_address']) {
                                $unsetDefaultSql = $con->prepare("UPDATE addresses SET default_address = 0 WHERE id_user = :id_user");
                                $unsetDefaultSql->execute([':id_user' => $userId]);
                            }

                            $sql = $con->prepare("INSERT INTO addresses (id_user, street, street2, city, province, company_name, name_address, last_name, cp, tel_address, default_address)
                                                        VALUES (:id_user, :street, :street2, :city, :province, :company_name, :name_address, :last_name, :cp, :tel_address, :default_address)");
                            $sql->execute([
                                ':id_user' => $userId,
                                ':street' => $addressData['street'],
                                ':street2' => $addressData['street2'],
                                ':city' => $addressData['city'],
                                ':province' => $addressData['province'],
                                ':company_name' => $addressData['company_name'],
                                ':name_address' => $addressData['name_address'],
                                ':last_name' => $addressData['last_name'],
                                ':cp' => $addressData['cp'],
                                ':tel_address' => $addressData['tel_address'],
                                ':default_address' => $addressData['default_address']
                            ]);

                            if ($sql->rowCount() > 0) {
                                enviarRespuesta(['success' => true, 'message' => 'Dirección agregada']);
                            } else {
                                enviarRespuesta(['success' => false, 'message' => 'No se pudo agregar la dirección']);
                            }
                        } elseif ($action == 'update-address-user') {

                            if ($addressData['default_address']) {
                                $unsetDefaultSql = $con->prepare("UPDATE addresses SET default_address = 0 WHERE id_user = :id_user");
                                $unsetDefaultSql->execute([':id_user' => $userId]);
                            }

                            $addressId = $addressData['id_address'];
                            $sql = $con->prepare("UPDATE addresses SET
                                                        street = :street,
                                                        street2 = :street2,
                                                        city = :city,
                                                        province = :province,
                                                        name_address = :name_address,
                                                        last_name = :last_name,
                                                        company_name = :company_name,
                                                        cp = :cp,
                                                        tel_address = :tel_address,
                                                        default_address = :default_address
                                                        WHERE id_address = :id_address AND id_user = :id_user");
                            $sql->execute([
                                ':street' => $addressData['street'],
                                ':street2' => $addressData['street2'],
                                ':city' => $addressData['city'],
                                ':province' => $addressData['province'],
                                ':name_address' => $addressData['name_address'],
                                ':last_name' => $addressData['last_name'],
                                ':company_name' => $addressData['company_name'],
                                ':cp' => $addressData['cp'],
                                ':tel_address' => $addressData['tel_address'],
                                ':default_address' => $addressData['default_address'],
                                ':id_address' => $addressId,
                                ':id_user' => $userId
                            ]);

                            if ($sql->rowCount() > 0) {
                                enviarRespuesta(['success' => true, 'message' => 'Dirección actualizada']);
                            } else {
                                enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la dirección']);
                            }
                        }
                    } catch (PDOException $e) {
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['status' => 'error', 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'delete-address-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset($data['data'])) {
                    $id_address = $data['data'];

                    try {
                        $sqlCheckDefault = $con->prepare("SELECT default_address, id_user FROM addresses WHERE id_address = :id_address");
                        $sqlCheckDefault->execute([':id_address' => $id_address]);
                        $addressInfo = $sqlCheckDefault->fetch(PDO::FETCH_ASSOC);

                        if ($addressInfo) {
                            $isDefault = $addressInfo['default_address'];
                            $userId = $addressInfo['id_user'];

                            $sql = $con->prepare("DELETE FROM addresses WHERE id_address = :id_address");
                            $sql->execute([':id_address' => $id_address]);

                            if ($sql->rowCount() > 0) {
                                if ($isDefault) {
                                    $sqlSetNewDefault = $con->prepare("UPDATE addresses
                                                                    SET default_address = 1
                                                                    WHERE id_user = :id_user
                                                                    LIMIT 1");
                                    $sqlSetNewDefault->execute([':id_user' => $userId]);
                                }

                                enviarRespuesta(['success' => true, 'message' => 'Dirección eliminada']);
                            } else {
                                enviarRespuesta(['success' => false, 'message' => 'No se pudo eliminar la dirección']);
                            }
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'Dirección no encontrada']);
                        }
                    } catch (PDOException $e) {
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'save-order':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset(
                    $data['data']['user']['id'],
                    $data['data']['products'],
                    $data['data']['total_price'],
                    $data['data']['address']['id_address'],
                    $data['data']['shipping']['id'],
                    $data['data']['state'],
                    $data['data']['date']
                )) {

                    $id_user = $data['data']['user']['id'];
                    $products = $data['data']['products'];
                    $total_price = $data['data']['total_price'];
                    $shipping_address = $data['data']['address']['id_address'];
                    $shipping_type = $data['data']['shipping']['id'];
                    $state = $data['data']['state'];
                    $date = date('Y-m-d H:i:s', strtotime($data['data']['date']));

                    try {
                        $sql = $con->prepare("INSERT INTO orders (id_user, total_price, shipping_address, shipping_type, state, date)
                                                VALUES (?, ?, ?, ?, ?, ?)");
                        $sql->execute([$id_user, $total_price, $shipping_address, $shipping_type, $state, $date]);

                        $order_id = $con->lastInsertId();

                        $product_sql = $con->prepare("INSERT INTO order_products (order_id, product_id, quantity) VALUES (?, ?, ?)");
                        foreach ($products as $product) {
                            $product_id = $product['product']['id'];
                            $quantity = $product['quantity'];
                            $product_sql->execute([$order_id, $product_id, $quantity]);
                        }

                        enviarRespuesta(['success' => true, 'message' => 'Orden registrada exitosamente']);
                    } catch (PDOException $e) {
                        enviarRespuesta(['success' => false, 'message' => 'Error al registrar la orden: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'register-product':  // Acciones de administrador  -productos
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset(
                    $data['id'],
                    $data['name'],
                    $data['price'],
                    $data['category'],
                    $data['description']
                )) {
                    $id = $data['id'];
                    $name = $data['name'];
                    $price = $data['price'];
                    $category = $data['category'];
                    $description = $data['description'];

                    $result = registerProduct($con, $data);
                    enviarRespuesta($result);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'update-product':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);


            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset(
                    $data['productId'],
                    $data['data']['id'],
                    $data['data']['name'],
                    $data['data']['category'],
                    $data['data']['description'],
                    $data['data']['price']
                )) {
                    $id = $data['productId'];
                    $new_id = $data['data']['id'];
                    $new_name = $data['data']['name'];
                    $new_category = $data['data']['category'];
                    $new_description = $data['data']['description'];
                    $new_price = $data['data']['price'];

                    $stmt = $con->prepare("SELECT COUNT(*) FROM products WHERE id = :id");
                    $stmt->execute([':id' => $id]);
                    if ($stmt->fetchColumn() == 0) {
                        enviarRespuesta(['success' => false, 'message' => 'El producto no existe']);
                        exit;
                    }

                    try {
                        $sql = $con->prepare("UPDATE products SET id=:new_id, name=:new_name, category=:new_category, description=:new_description, price=:new_price WHERE id = :id");
                        $sql->execute([
                            ':new_id' => $new_id,
                            ':new_name' => $new_name,
                            ':new_category' => $new_category,
                            ':new_description' => $new_description,
                            ':new_price' => $new_price,
                            ':id' => $id
                        ]);

                        if ($sql->rowCount() > 0) {
                            enviarRespuesta(['success' => true, 'message' => 'Información actualizada']);
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la información']);
                        }
                    } catch (PDOException $e) {

                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'delete-product':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['productId'])) {
                    $id = $data['productId'];

                    $sql = $con->prepare("DELETE FROM products WHERE id = :id");
                    $sql->execute([':id' => $id]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'Producto eliminado exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo eliminar el producto']);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'update-price':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['percentage'])) {
                    $percentage = $data['percentage'];
                    $productIds = $data['productIds'] ?? [];

                    $factor = 1 + ($percentage / 100);

                    if (empty($productIds)) {
                        $sql = $con->prepare("UPDATE products SET price = price * :factor");
                        $sql->execute([':factor' => $factor]);
                    } else {
                        $placeholders = [];
                        $params = [':factor' => $factor];

                        foreach ($productIds as $index => $id) {
                            $paramName = ":id$index";
                            $placeholders[] = $paramName;
                            $params[$paramName] = $id;
                        }

                        $placeholdersString = implode(',', $placeholders);
                        $sql = $con->prepare("UPDATE products SET price = price * :factor WHERE id IN ($placeholdersString)");
                        $sql->execute($params);
                    }

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'Precios actualizados exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la lista de precios']);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;

        case 'upload-images-products':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                if (isset($_POST['productId'])) {
                    $productId = $_POST['productId'];
                    $updatedImages = [];
                    $deletedImages = $_POST['deletedImages'] ?? [];

                    if (!empty($_POST['deletedImages'])) {
                        foreach ($_POST['deletedImages'] as $imageId) {
                            $deleteQuery = "DELETE FROM products_images WHERE id_img = ?";
                            $sql = $con->prepare($deleteQuery);
                            $sql->execute([$imageId]);
                        }
                    }

                    foreach ($_POST as $key => $value) {
                        if (strpos($key, 'existingImageId') === 0) {
                            $imageId = $value;
                            $priorityKey = str_replace('existingImageId', 'priority', $key);
                            $priority = $_POST[$priorityKey] ?? null;

                            if ($priority !== null) {
                                $sql = $con->prepare("UPDATE products_images SET priority = ? WHERE id_img = ? AND product_id = ?");
                                $sql->execute([$priority, $imageId, $productId]);
                                $updatedImages[] = $imageId;
                            }
                        }
                    }

                    // Procesar nuevas imágenes
                    foreach ($_FILES as $key => $file) {
                        if (strpos($key, 'image') === 0) {
                            $priorityKey = str_replace('image', 'priority', $key);
                            $priority = $_POST[$priorityKey] ?? null;

                            if ($priority !== null && $file['error'] === UPLOAD_ERR_OK) {
                                $filePath = '/uploads/products/' . basename($file['name']);
                                if (move_uploaded_file($file['tmp_name'], __DIR__ . $filePath)) {
                                    // Insertar la nueva imagen en la base de datos
                                    $sql = $con->prepare("INSERT INTO products_images (product_id, img_url, priority) VALUES (?, ?, ?)");
                                    $sql->execute([$productId, $filePath, $priority]);
                                    $updatedImages[] = $con->lastInsertId();
                                }
                            }
                        }
                    }

                    echo json_encode(['success' => true, 'updatedImages' => $updatedImages]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Faltan datos necesarios.']);
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'Token inválido.']);
            }
            break;

        case 'register-prod-and-img':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                if (isset(
                    $_POST['id'],
                    $_POST['name'],
                    $_POST['price'],
                    $_POST['category'],
                    $_POST['description'],
                )) {
                    $data = [
                        'id' => $_POST['id'],
                        'name' => $_POST['name'],
                        'price' => $_POST['price'],
                        'category' => $_POST['category'],
                        'description' => $_POST['description'],
                    ];

                    $productId = $_POST['id'];

                    // Iniciar una transacción
                    $con->beginTransaction();

                    $result = registerProduct($con, $data);
                    if (!$result['success']) {
                        $con->rollBack();
                        enviarRespuesta($result);
                        break;
                    }

                    // Procesar todas las imágenes enviadas
                    $imageUploadSuccess = true;
                    foreach ($_FILES as $key => $file) {
                        if (strpos($key, 'image') === 0) {
                            $index = str_replace('image', '', $key);
                            $priorityKey = 'priority' . $index;

                            if (!isset($_POST[$priorityKey])) {
                                $imageUploadSuccess = false;
                                break;
                            }

                            $priority = $_POST[$priorityKey];
                            $filePath = '/uploads/products/' . basename($file['name']);
                            if (move_uploaded_file($file['tmp_name'], __DIR__ . $filePath)) {
                                // Insertar la nueva imagen en la base de datos
                                $sql = $con->prepare("INSERT INTO products_images (product_id, img_url, priority) VALUES (?, ?, ?)");
                                $sql->execute([$productId, $filePath, $priority]);
                                $updatedImages[] = $con->lastInsertId();
                            }
                        }
                    }

                    if (!$imageUploadSuccess) {
                        $con->rollBack();
                        enviarRespuesta(['success' => false, 'message' => 'Error al subir imágenes']);
                        break;
                    }

                    // Confirmar la transacción
                    $con->commit();
                    enviarRespuesta(['success' => true, 'message' => 'Producto e imagen registrados correctamente']);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'change-approved': // -usuarios
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['id'])) {
                    $id = $data['id'];

                    $sql = $con->prepare("UPDATE users SET approved = NOT approved, new = 0 WHERE id = :id");
                    $sql->execute([':id' => $id]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'Estado de aprovación del usuario modificado exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo modificar el estado de aprovación del usuario']);
                    }
                }
            }
            break;
        case 'change-role':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['id'])) {
                    $id = $data['id'];

                    $sql = $con->prepare("
                        UPDATE users
                        SET role = CASE
                            WHEN role = 'user' THEN 'admin'
                            ELSE 'user'
                        END,
                        new = 0
                        WHERE id = :id
                    ");
                    $sql->execute([':id' => $id]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'Estado de aprovación del usuario modificado exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo modificar el estado de aprovación del usuario']);
                    }
                }
            }
            break;

        case 'delete-user':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['id'])) {
                    $id = $data['id'];

                    $sql = $con->prepare("DELETE FROM users WHERE id = :id");
                    $sql->execute([':id' => $id]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'El usuario se eliminó exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo eliminar el usuario']);
                    }
                }
            }
            break;
        case 'update-state-order': // -ordenes
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['orderId'], $data['newState'])) {
                    $id_order = $data['orderId'];
                    $state = $data['newState'];

                    $sql = $con->prepare("UPDATE orders SET state = :state WHERE id_order = :id_order");
                    $sql->execute([
                        ':id_order' => $id_order,
                        ':state' => $state
                    ]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'El estado de la orden se actualizó exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar el estado de la orden']);
                    }
                }
            }
            break;
        case 'update-new':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['orderId'])) {
                    $orderId = $data['orderId'];

                    $sql = $con->prepare("UPDATE orders SET new = 0 WHERE id_order = :orderId");
                    $sql->execute([':orderId' => $orderId]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'Orden actualizada exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar la orden']);
                    }
                }
            }
            break;

        case 'delete-order':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['orderId'])) {
                    $id_order = $data['orderId'];

                    $sql = $con->prepare("DELETE FROM orders WHERE id_order = :id_order");
                    $sql->execute([
                        ':id_order' => $id_order,
                    ]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'La orden se eliminó exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se eliminar la orden']);
                    }
                }
            }
            break;
        case 'add-gallery': // -galería
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                // Verificar si el archivo fue enviado correctamente
                if (!empty($_FILES['image']['tmp_name']) && isset($_POST['priority'])) {
                    $image = $_FILES['image'];
                    $priority = intval($_POST['priority']);

                    // Validar tipo de archivo
                    $allowedTypes = ['image/jpeg', 'image/png'];
                    if (!in_array($image['type'], $allowedTypes)) {
                        echo json_encode([
                            'success' => false,
                            'message' => 'Tipo de archivo no permitido.',
                        ]);
                        break;
                    }

                    // Crear directorio si no existe
                    $targetDir = './uploads/img-gallery/';

                    // Generar un nombre único para el archivo
                    $fileName = uniqid() . "_" . basename($image['name']);
                    $targetFile = $targetDir . $fileName;

                    if (move_uploaded_file($image['tmp_name'], $targetFile)) {
                        // Insertar datos en la base de datos
                        $sql = $con->prepare("INSERT INTO gallery_images (img_url, priority) VALUES (?, ?)");
                        if ($sql->execute([$targetFile, $priority])) {
                            echo json_encode([
                                'success' => true,
                                'message' => 'Imagen añadida exitosamente.',
                            ]);
                        } else {
                            echo json_encode([
                                'success' => false,
                                'message' => 'Error al guardar la imagen en la base de datos.',
                            ]);
                        }
                    } else {
                        echo json_encode([
                            'success' => false,
                            'message' => 'Error al mover el archivo subido.',
                        ]);
                    }
                } else {
                    echo json_encode([
                        'success' => false,
                        'message' => 'Archivo o prioridad no enviados.',
                    ]);
                }
            }

            break;
        case 'update-gallery':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $payload = json_decode(file_get_contents('php://input'), true);
                $updatedImages = $payload['images'] ?? [];

                if (!empty($updatedImages)) {
                    try {
                        $con->beginTransaction();

                        $imageIds = array_map(function ($img) {
                            return $img['id'];
                        }, $updatedImages);
                        $placeholders = rtrim(str_repeat('?, ', count($imageIds)), ', ');

                        $sqlDelete = "DELETE FROM gallery_images WHERE id NOT IN ($placeholders)";
                        $stmtDelete = $con->prepare($sqlDelete);
                        $stmtDelete->execute($imageIds);

                        foreach ($updatedImages as $index => $image) {
                            $sqlUpdate = "UPDATE gallery_images SET priority = ? WHERE id = ?";
                            $stmtUpdate = $con->prepare($sqlUpdate);
                            $stmtUpdate->execute([($index + 1), $image['id']]);
                        }

                        $con->commit();
                        echo json_encode(['success' => true, 'message' => 'Galería actualizada correctamente']);
                    } catch (PDOException $e) {
                        $con->rollBack();
                        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
                    }
                } else {
                    echo json_encode(['success' => false, 'message' => 'No images provided.']);
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'Invalid token.']);
            }
            break;
        case 'update_companyInfo': // -cuenta
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents('php://input'), true);

                if (isset($data['email'], $data['store_address'], $data['tel'])) {
                    try {
                        // Preparar la consulta
                        $sql = "UPDATE company_info SET value = ? WHERE `key` = ?";
                        $stmt = $con->prepare($sql);

                        // Ejecutar una consulta para cada par key-value
                        foreach ($data as $key => $value) {
                            $stmt->execute([$value, $key]);
                        }

                        enviarRespuesta(['success' => true, 'message' => 'Información actualizada']);
                    } catch (PDOException $e) {
                        error_log('Database error: ' . $e->getMessage());
                        enviarRespuesta(['success' => false, 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
                    }
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido o expirado']);
            }
            break;
        case 'update_social':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                if ($_SERVER['REQUEST_METHOD'] === 'POST') {

                    if (isset($_FILES['img_social']) && isset($_POST['id']) && isset($_POST['social_url'])) {
                        // Obtener la información del formulario
                        $id = $_POST['id'];
                        $social_url = $_POST['social_url'];
                        $img_social = $_FILES['img_social'];

                        // Verificar si el archivo se subió correctamente
                        if ($img_social['error'] === UPLOAD_ERR_OK) {
                            // Directorio donde guardarás la imagen
                            $filePath = '/uploads/social/' . basename($img_social['name']); // Corregir el uso de variable

                            // Mover el archivo a su ubicación final
                            if (move_uploaded_file($img_social['tmp_name'], __DIR__ . $filePath)) {
                                // Verificar si el registro ya existe en la base de datos
                                $sqlCheck = "SELECT * FROM social_networks WHERE id = :id";
                                $stmtCheck = $con->prepare($sqlCheck);
                                $stmtCheck->execute([':id' => $id]);
                                $existingRecord = $stmtCheck->fetch();

                                if ($existingRecord) {
                                    // Si el registro existe, actualizarlo
                                    $sqlUpdate = "UPDATE social_networks SET img_social = :img_social, url = :social_url WHERE id = :id";
                                    $stmtUpdate = $con->prepare($sqlUpdate);
                                    $stmtUpdate->execute([
                                        ':img_social' => $filePath, // Usar la ruta definida en $filePath
                                        ':social_url' => $social_url,
                                        ':id' => $id
                                    ]);
                                    enviarRespuesta(['success' => true, 'message' => 'Red social actualizada correctamente']);
                                } else {
                                    // Si el registro no existe, insertarlo
                                    $sqlInsert = "INSERT INTO social_networks (id, img_social, url) VALUES (:id, :img_social, :social_url)";
                                    $stmtInsert = $con->prepare($sqlInsert);
                                    $stmtInsert->execute([
                                        ':id' => $id,
                                        ':img_social' => $filePath,
                                        ':social_url' => $social_url
                                    ]);
                                    enviarRespuesta(['success' => true, 'message' => 'Red social agregada correctamente']);
                                }
                            } else {
                                enviarRespuesta(['success' => false, 'message' => 'Error al subir el archivo']);
                            }
                        } else {
                            enviarRespuesta(['success' => false, 'message' => 'Error en la subida del archivo']);
                        }
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'Datos incompletos']);
                    }
                }
            }
            break;
        case 'delete-social':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (isset($data['id'])) {
                    $id = $data['id'];

                    $sql = $con->prepare("DELETE FROM social_networks WHERE id = :id");
                    $sql->execute([
                        ':id' => $id,
                    ]);

                    if ($sql->rowCount() > 0) {
                        enviarRespuesta(['success' => true, 'message' => 'La red social se eliminó exitosamente']);
                    } else {
                        enviarRespuesta(['success' => false, 'message' => 'No se eliminar la red social']);
                    }
                }
            }
            break;
        case 'update-shipping':
            $authHeader = getallheaders();
            list($jwt) = @sscanf($authHeader['Authorization'] ?? '', 'Bearer %s');
            $decoded = verificarToken($jwt);

            if ($decoded) {
                $data = json_decode(file_get_contents("php://input"), true);

                if (!isset($data['updatedShipping']) || !is_array($data['updatedShipping'])) {
                    enviarRespuesta(['success' => false, 'message' => 'Datos inválidos']);
                    break;
                }

                $updates = $data['updatedShipping'];
                $anyUpdateFailed = false;

                foreach ($updates as $update) {
                    if (isset($update['id_shipping'], $update['description'], $update['price'])) {
                        $id_shipping = $update['id_shipping'];
                        $description = $update['description'];
                        $price = $update['price'];

                        try {
                            $sql = $con->prepare("UPDATE shipping SET description = :description, price = :price  WHERE id_shipping = :id_shipping");

                            $sql->execute([
                                ':id_shipping' => $id_shipping,
                                ':description' => $description,
                                ':price' => $price,
                            ]);

                            if (!$sql) {
                                $anyUpdateFailed = true;
                            }

                        } catch (PDOException $e) {
                            $anyUpdateFailed = true;
                            error_log("Error en la actualización de envío: " . $e->getMessage());
                        }
                    } else {
                        $anyUpdateFailed = true;
                    }
                }

                if (!$anyUpdateFailed) {
                    enviarRespuesta(['success' => true, 'message' => 'La información de envío se actualizó exitosamente']);
                } else {
                    enviarRespuesta(['success' => false, 'message' => 'No se pudo actualizar toda la información']);
                }
            } else {
                enviarRespuesta(['success' => false, 'message' => 'Token inválido']);
            }
            break;

        default:
            enviarRespuesta(['success' => false, 'error' => 'acción no válida']);
            break;
    }
} else {
    enviarRespuesta(['error' => 'Acción no válida']);
}
