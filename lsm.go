package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
)

const (
	configDir  = ".lsm"
	configExt  = ".profile"
	snFlag     = "-sn"
	bufferSize = 4096
)

type Profile struct {
	Nickname string `json:"nickname"`
	Key      string `json:"key"`
	Password string `json:"-"`
}

var (
	clients     = make(map[net.Conn]string)
	clientsMux  sync.Mutex
	currentNick string
	showNick    bool
)

func normalizeKey(key string) []byte {
    // Хешируем ключ с помощью SHA-256 чтобы получить ровно 32 байта
    hash := sha256.Sum256([]byte(key))
    return hash[:]
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	switch os.Args[1] {
	case "genProfile":
		if len(os.Args) < 3 {
			fmt.Println("Необходимо указать имя профиля")
			return
		}
		generateProfile(os.Args[2])
	case "server":
		if len(os.Args) < 4 {
			fmt.Println("Использование: lsm server interface:port profile ?-sn")
			return
		}
		showNick = contains(os.Args, snFlag)
		startServer(os.Args[2], os.Args[3])
	case "client":
		if len(os.Args) < 4 {
			fmt.Println("Использование: lsm client ip:port profile ?-sn")
			return
		}
		showNick = contains(os.Args, snFlag)
		startClient(os.Args[2], os.Args[3])
	default:
		printHelp()
	}
}

func printHelp() {
	fmt.Println("Использование:")
	fmt.Println("  lsm genProfile <name> - создать новый профиль")
	fmt.Println("  lsm server <interface:port> <profile> ?-sn - запустить сервер")
	fmt.Println("  lsm client <ip:port> <profile> ?-sn - подключиться к серверу")
	fmt.Println("Опции:")
	fmt.Println("  -sn - показывать никнейм отправителя")
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func generateProfile(name string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Введите никнейм: ")
	nickname, _ := reader.ReadString('\n')
	nickname = strings.TrimSpace(nickname)

	fmt.Print("Введите ключ шифрования: ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)


	fmt.Print("Введите пароль для шифрования профиля: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	profile := Profile{
		Nickname: nickname,
		Key:      key,
		Password: password,
	}

	if err := saveProfile(name, &profile); err != nil {
		fmt.Printf("Ошибка при сохранении профиля: %v\n", err)
		return
	}

	fmt.Printf("Профиль '%s' успешно создан\n", name)
}

func saveProfile(name string, profile *Profile) error {
	usr, err := user.Current()
	if err != nil {
		return err
	}

	configPath := filepath.Join(usr.HomeDir, configDir)
	if err := os.MkdirAll(configPath, 0700); err != nil {
		return err
	}

	profilePath := filepath.Join(configPath, name+configExt)

	// Шифруем данные профиля перед сохранением
	encryptedData, err := encryptProfile(profile)
	if err != nil {
		return err
	}

	return os.WriteFile(profilePath, encryptedData, 0600)
}

func encryptProfile(profile *Profile) ([]byte, error) {
	data, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}

	key := sha256.Sum256([]byte(profile.Password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

func loadProfile(name string) (*Profile, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	profilePath := filepath.Join(usr.HomeDir, configDir, name+configExt)
	encryptedData, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Введите пароль для профиля: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	profile, err := decryptProfile(encryptedData, password)
	if err != nil {
		return nil, err
	}

	profile.Password = password
	return profile, nil
}

func decryptProfile(encryptedData []byte, password string) (*Profile, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("неверные данные профиля")
	}

	nonce, encryptedData := encryptedData[:nonceSize], encryptedData[nonceSize:]
	data, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, errors.New("неверный пароль")
	}

	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

func startServer(addr string, profileName string) {
	profile, err := loadProfile(profileName)
	if err != nil {
		fmt.Printf("Ошибка загрузки профиля: %v\n", err)
		return
	}

	currentNick = profile.Nickname
	key := normalizeKey(profile.Key)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Ошибка запуска сервера: %v\n", err)
		return
	}
	defer listener.Close()

	fmt.Printf("Сервер запущен на %s. Ник: %s\n", addr, currentNick)

	go handleServerInput(key)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Ошибка подключения: %v\n", err)
			continue
		}

		go handleClient(conn, key, profile.Nickname)
	}
}

func handleServerInput(key []byte) {
	reader := bufio.NewReader(os.Stdin)
	for {
		msg, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Ошибка чтения ввода: %v\n", err)
			continue
		}

		msg = strings.TrimSpace(msg)
		if msg == "" {
			continue
		}

		encryptedMsg, err := encryptMessage(key, currentNick+": "+msg)
		if err != nil {
			fmt.Printf("Ошибка шифрования: %v\n", err)
			continue
		}

		broadcast(encryptedMsg)
	}
}

func handleClient(conn net.Conn, key []byte, serverNick string) {
	defer conn.Close()

	// Получаем ник клиента
	nick, err := readMessage(conn, key)
	if err != nil {
		fmt.Printf("Ошибка получения ника клиента: %v\n", err)
		return
	}

	clientsMux.Lock()
	clients[conn] = nick
	clientsMux.Unlock()

	fmt.Printf("%s подключился\n", nick)

	// Отправляем ник сервера клиенту
	if err := sendMessage(conn, key, serverNick); err != nil {
		fmt.Printf("Ошибка отправки ника сервера: %v\n", err)
		return
	}

	for {
		encryptedMsg, err := readMessage(conn, key)
		if err != nil {
			clientsMux.Lock()
			delete(clients, conn)
			clientsMux.Unlock()
			fmt.Printf("%s отключился\n", nick)
			return
		}

		msg := encryptedMsg
		if showNick {
			msg = nick + ": " + msg
		}

		fmt.Println(msg)

		// Шифруем снова для отправки другим клиентам
		encryptedBroadcast, err := encryptMessage(key, msg)
		if err != nil {
			fmt.Printf("Ошибка шифрования: %v\n", err)
			continue
		}

		broadcastToOthers(conn, encryptedBroadcast)
	}
}

func broadcast(msg []byte) {
	clientsMux.Lock()
	defer clientsMux.Unlock()

	for conn := range clients {
		if _, err := conn.Write(msg); err != nil {
			fmt.Printf("Ошибка отправки сообщения: %v\n", err)
		}
	}
}

func broadcastToOthers(sender net.Conn, msg []byte) {
	clientsMux.Lock()
	defer clientsMux.Unlock()

	for conn := range clients {
		if conn != sender {
			if _, err := conn.Write(msg); err != nil {
				fmt.Printf("Ошибка отправки сообщения: %v\n", err)
			}
		}
	}
}

func startClient(addr string, profileName string) {
    profile, err := loadProfile(profileName)
    if err != nil {
        fmt.Printf("Ошибка загрузки профиля: %v\n", err)
        return
    }

    currentNick = profile.Nickname
	key := normalizeKey(profile.Key)

    conn, err := net.Dial("tcp", addr)
    if err != nil {
        fmt.Printf("Ошибка подключения к серверу: %v\n", err)
        return
    }
    defer conn.Close()

    // Отправляем свой ник серверу
    if err := sendMessage(conn, key, currentNick); err != nil {
        fmt.Printf("Ошибка отправки ника: %v\n", err)
        return
    }

    // Получаем ник сервера
    serverNick, err := readMessage(conn, key)
    if err != nil {
        fmt.Printf("Ошибка получения ника сервера: %v\n", err)
        return
    }

    fmt.Printf("Подключено к серверу %s. Ник сервера: %s\n", addr, serverNick)

    go handleClientMessages(conn, key)

    reader := bufio.NewReader(os.Stdin)
    for {
        msg, err := reader.ReadString('\n')
        if err != nil {
            fmt.Printf("Ошибка чтения ввода: %v\n", err)
            continue
        }

        msg = strings.TrimSpace(msg)
        if msg == "" {
            continue
        }

        // Убрано лишнее объявление encryptedMsg, так как оно не использовалось
        if err := sendMessage(conn, key, msg); err != nil {
            fmt.Printf("Ошибка отправки сообщения: %v\n", err)
            return
        }
    }
}
 
func handleClientMessages(conn net.Conn, key []byte) {
	for {
		msg, err := readMessage(conn, key)
		if err != nil {
			fmt.Printf("Соединение с сервером прервано: %v\n", err)
			os.Exit(0)
		}

		fmt.Println(msg)
	}
}
func encryptMessage(key []byte, message string) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    encrypted := gcm.Seal(nonce, nonce, []byte(message), nil)
    return []byte(hex.EncodeToString(encrypted) + "\n"), nil
}

func decryptMessage(key []byte, encryptedHex string) (string, error) {
    encrypted, err := hex.DecodeString(encryptedHex)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(encrypted) < nonceSize {
        return "", errors.New("неверные зашифрованные данные")
    }

    nonce, encrypted := encrypted[:nonceSize], encrypted[nonceSize:]
    decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
    if err != nil {
        return "", err
    }

    return string(decrypted), nil
}

func sendMessage(conn net.Conn, key []byte, message string) error {
    encrypted, err := encryptMessage(key, message)
    if err != nil {
        return err
    }

    _, err = conn.Write(encrypted)
    return err
}


func readMessage(conn net.Conn, key []byte) (string, error) {
	reader := bufio.NewReader(conn)
	encryptedHex, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	encryptedHex = strings.TrimSpace(encryptedHex)
	return decryptMessage(key, encryptedHex)
}
