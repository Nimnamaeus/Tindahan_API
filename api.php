<?php
require_once 'vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Database connection
$host = 'localhost';
$db = 'clothing';
$user = 'root';
$pass = '';

try {
    $conn = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// Helper functions
function getUserIdFromToken() {
    $headers = getallheaders();
    
    if (!isset($headers['Authorization'])) {
        throw new Exception('No authorization header found');
    }

    $authHeader = $headers['Authorization'];
    $token = str_replace('Bearer ', '', $authHeader);
    
    if (empty($token)) {
        throw new Exception('Token is empty');
    }

    try {
        $secret_key = "your_strong_secret_key_123!@#";
        $decoded = JWT::decode($token, new Key($secret_key, 'HS256'));
        return $decoded->user_id;
    } catch (Exception $e) {
        throw new Exception('Token validation failed: ' . $e->getMessage());
    }
}

function createUserProduct($conn, $data) {
    try {
        $user_id = getUserIdFromToken();
        
        $stmt = $conn->prepare("INSERT INTO products (product_name, description, price, 
                                                    category_id, size, color, material, 
                                                    user_id, date_added) 
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURDATE())");
        
        $result = $stmt->execute([
            $data['product_name'],
            $data['description'],
            $data['price'],
            $data['category_id'],
            $data['size'],
            $data['color'],
            $data['material'],
            $user_id
        ]);
        
        return $result;
    } catch (Exception $e) {
        echo json_encode(['error' => 'Failed to create product: ' . $e->getMessage()]);
        return false;
    }
}

// Main routing
$path = $_GET['path'] ?? '';

switch ($path) {
    case 'login':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            try {
                $data = json_decode(file_get_contents('php://input'), true);
                
                if (!isset($data['email']) || !isset($data['password'])) {
                    echo json_encode(['error' => 'Email and password are required']);
                    exit;
                }

                $email = $data['email'];
                $password = $data['password'];
                
                $stmt = $conn->prepare("SELECT u.user_id, u.password, r.role_name 
                                      FROM users u 
                                      JOIN roles r ON u.role_id = r.role_id 
                                      WHERE u.email = ?");
                $stmt->execute([$email]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($user) {
                    $secret_key = "your_strong_secret_key_123!@#";
                    putenv("JWT_SECRET=$secret_key");
                    
                    $payload = [
                        'user_id' => $user['user_id'],
                        'role' => $user['role_name'],
                        'exp' => time() + (60 * 60)
                    ];
                    
                    $jwt = JWT::encode($payload, $secret_key, 'HS256');
                    
                    echo json_encode([
                        'success' => true,
                        'token' => $jwt,
                        'role' => $user['role_name']
                    ]);
                } else {
                    echo json_encode(['error' => 'Invalid credentials']);
                }
            } catch (Exception $e) {
                echo json_encode(['error' => 'Login failed: ' . $e->getMessage()]);
            }
        }
        break;

    case 'user/products':
        switch ($_SERVER['REQUEST_METHOD']) {
            case 'GET':
                try {
                    $user_id = getUserIdFromToken();
                    
                    // Prepare and execute query to get user's products
                    $stmt = $conn->prepare("SELECT 
                        product_id,
                        product_name,
                        description,
                        price,
                        category_id,
                        size,
                        color,
                        material,
                        date_added
                        FROM products 
                        WHERE user_id = ?
                        ORDER BY date_added DESC");
                    
                    $stmt->execute([$user_id]);
                    $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    if ($products) {
                        echo json_encode([
                            'success' => true,
                            'products' => $products
                        ]);
                    } else {
                        echo json_encode([
                            'success' => true,
                            'products' => [],
                            'message' => 'No products found'
                        ]);
                    }
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode([
                        'error' => 'Failed to fetch products: ' . $e->getMessage()
                    ]);
                }
                break;

            case 'POST':
                $data = json_decode(file_get_contents('php://input'), true);
                if (createUserProduct($conn, $data)) {
                    echo json_encode(['success' => true, 'message' => 'Product created successfully']);
                } else {
                    http_response_code(500);
                    echo json_encode(['error' => 'Failed to create product']);
                }
                break;

            case 'PUT':
                try {
                    $user_id = getUserIdFromToken();
                    $data = json_decode(file_get_contents('php://input'), true);
                    $product_id = $_GET['id'] ?? null;
                    
                    if (!$product_id) {
                        http_response_code(400);
                        echo json_encode(['error' => 'Product ID is required']);
                        break;
                    }
                    
                    // Verify product belongs to user
                    $stmt = $conn->prepare("SELECT user_id FROM products WHERE product_id = ?");
                    $stmt->execute([$product_id]);
                    $product = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$product || $product['user_id'] !== $user_id) {
                        http_response_code(403);
                        echo json_encode(['error' => 'Unauthorized to edit this product']);
                        break;
                    }
                    
                    $stmt = $conn->prepare("UPDATE products 
                                          SET product_name = ?, 
                                              description = ?, 
                                              price = ?,
                                              category_id = ?, 
                                              size = ?, 
                                              color = ?, 
                                              material = ?
                                          WHERE product_id = ? AND user_id = ?");
                    
                    $result = $stmt->execute([
                        $data['product_name'],
                        $data['description'],
                        $data['price'],
                        $data['category_id'],
                        $data['size'],
                        $data['color'],
                        $data['material'],
                        $product_id,
                        $user_id
                    ]);
                    
                    if ($result) {
                        echo json_encode([
                            'success' => true, 
                            'message' => 'Product updated successfully'
                        ]);
                    } else {
                        throw new Exception('Failed to update product');
                    }
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode(['error' => $e->getMessage()]);
                }
                break;

            case 'DELETE':
                try {
                    $user_id = getUserIdFromToken();
                    $product_id = $_GET['id'] ?? null;
                    
                    if (!$product_id) {
                        http_response_code(400);
                        echo json_encode(['error' => 'Product ID is required']);
                        break;
                    }
                    
                    // Verify product belongs to user and delete it
                    $stmt = $conn->prepare("DELETE FROM products 
                                          WHERE product_id = ? AND user_id = ?");
                    $result = $stmt->execute([$product_id, $user_id]);
                    
                    if ($stmt->rowCount() > 0) {
                        echo json_encode([
                            'success' => true, 
                            'message' => 'Product deleted successfully'
                        ]);
                    } else {
                        http_response_code(404);
                        echo json_encode([
                            'error' => 'Product not found or unauthorized'
                        ]);
                    }
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode(['error' => $e->getMessage()]);
                }
                break;

            default:
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed']);
                break;
        }
        break;

    case 'products':
        switch ($_SERVER['REQUEST_METHOD']) {
            case 'GET':
                try {
                    $product_id = $_GET['id'] ?? null;
                    $search = $_GET['search'] ?? null;
                    
                    if ($product_id) {
                        // Get single product
                        $stmt = $conn->prepare("SELECT 
                            p.product_id,
                            p.product_name,
                            p.description,
                            p.price,
                            p.category_id,
                            pc.category_name,
                            p.size,
                            p.color,
                            p.material,
                            p.date_added
                        FROM products p
                        LEFT JOIN product_category pc ON p.category_id = pc.category_id
                        WHERE p.product_id = ?");
                        
                        $stmt->execute([$product_id]);
                        $product = $stmt->fetch(PDO::FETCH_ASSOC);
                        
                        if ($product) {
                            echo json_encode([
                                'success' => true,
                                'product' => $product
                            ]);
                        } else {
                            http_response_code(404);
                            echo json_encode([
                                'error' => 'Product not found'
                            ]);
                        }
                    } else {
                        // Get all products with category info
                        $query = "SELECT 
                            p.product_id,
                            p.product_name,
                            p.description,
                            p.price,
                            p.category_id,
                            pc.category_name,
                            p.size,
                            p.color,
                            p.material,
                            p.date_added
                        FROM products p
                        LEFT JOIN product_category pc ON p.category_id = pc.category_id
                        WHERE 1=1";
                        
                        $params = [];
                        
                        if (isset($_GET['category'])) {
                            $query .= " AND p.category_id = ?";
                            $params[] = $_GET['category'];
                        }
                        
                        if ($search) {
                            $query .= " AND (p.product_name LIKE ? OR p.description LIKE ?)";
                            $params[] = "%$search%";
                            $params[] = "%$search%";
                        }
                        
                        $query .= " ORDER BY p.date_added DESC";
                        
                        $stmt = $conn->prepare($query);
                        $stmt->execute($params);
                        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
                        
                        echo json_encode([
                            'success' => true,
                            'products' => $products,
                            'count' => count($products)
                        ]);
                    }
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode([
                        'error' => 'Failed to fetch products: ' . $e->getMessage()
                    ]);
                }
                break;
        }
        break;

    case 'categories':
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            try {
                $stmt = $conn->prepare("SELECT * FROM product_category ORDER BY name");
                $stmt->execute();
                $categories = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                echo json_encode([
                    'success' => true,
                    'categories' => $categories
                ]);
            } catch (Exception $e) {
                http_response_code(500);
                echo json_encode([
                    'error' => 'Failed to fetch categories: ' . $e->getMessage()
                ]);
            }
        }
        break;

    case 'admin/products':
        // Verify admin token first
        try {
            $headers = getallheaders();
            if (!isset($headers['Authorization'])) {
                throw new Exception('No authorization header found');
            }

            $token = str_replace('Bearer ', '', $headers['Authorization']);
            $secret_key = "your_strong_secret_key_123!@#";
            $decoded = JWT::decode($token, new Key($secret_key, 'HS256'));
            
            if ($decoded->role !== 'Admin') {
                throw new Exception('Unauthorized access');
            }

            switch ($_SERVER['REQUEST_METHOD']) {
                case 'PUT':
                    try {
                        $product_id = $_GET['id'] ?? null;
                        $data = json_decode(file_get_contents('php://input'), true);
                        
                        if (!$product_id) {
                            http_response_code(400);
                            echo json_encode(['error' => 'Product ID is required']);
                            break;
                        }
                        
                        $stmt = $conn->prepare("UPDATE products 
                                              SET product_name = ?, 
                                                  description = ?, 
                                                  price = ?,
                                                  category_id = ?, 
                                                  size = ?, 
                                                  color = ?, 
                                                  material = ?
                                              WHERE product_id = ?");
                        
                        $result = $stmt->execute([
                            $data['product_name'],
                            $data['description'],
                            $data['price'],
                            $data['category_id'],
                            $data['size'],
                            $data['color'],
                            $data['material'],
                            $product_id
                        ]);
                        
                        if ($result) {
                            echo json_encode([
                                'success' => true, 
                                'message' => 'Product updated successfully'
                            ]);
                        } else {
                            throw new Exception('Failed to update product');
                        }
                    } catch (Exception $e) {
                        http_response_code(500);
                        echo json_encode(['error' => $e->getMessage()]);
                    }
                    break;

                case 'DELETE':
                    try {
                        $product_id = $_GET['id'] ?? null;
                        
                        if (!$product_id) {
                            http_response_code(400);
                            echo json_encode(['error' => 'Product ID is required']);
                            break;
                        }
                        
                        $stmt = $conn->prepare("DELETE FROM products WHERE product_id = ?");
                        $result = $stmt->execute([$product_id]);
                        
                        if ($result) {
                            echo json_encode([
                                'success' => true, 
                                'message' => 'Product deleted successfully'
                            ]);
                        } else {
                            throw new Exception('Failed to delete product');
                        }
                    } catch (Exception $e) {
                        http_response_code(500);
                        echo json_encode(['error' => $e->getMessage()]);
                    }
                    break;

                default:
                    http_response_code(405);
                    echo json_encode(['error' => 'Method not allowed']);
                    break;
            }
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized: ' . $e->getMessage()]);
        }
        break;

    default:
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint not found']);
        break;
}


