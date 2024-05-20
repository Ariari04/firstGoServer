package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

var jwtKey = []byte("my_secret_key_is_LOVE_forever")

type Claims struct {
	Role  string `json:"role"`
	Email string `json:"email"`

	jwt.StandardClaims
}

type StudentToGet struct {
	ID      primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name    string             `json:"name"`
	Surname string             `json:"surname"`
	Passwd  string             `json:"passwd"`
	Email   string             `json:"email"`
	GroupID primitive.ObjectID `json:"group_id"`
}
type Person struct {
	ID      primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name    string             `json:"name"`
	Surname string             `json:"surname"`
	Passwd  string             `json:"passwd"`
	Age     int                `json:"age"`
	Email   string             `json:"email"`
}

type Group struct {
	ID   primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name string             `json:"name"`
}

type Student struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	PersonID primitive.ObjectID `json:"person_id"`
	GroupID  primitive.ObjectID `json:"group_id"`
}

type Subject struct {
	ID   primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name string             `json:"name"`
}

type Access struct {
	ID         primitive.ObjectID   `json:"id" bson:"_id,omitempty"`
	SubjectIDs []primitive.ObjectID `json:"subject_ids"`
}

type Teacher struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	PersonID primitive.ObjectID `json:"person_id"`
	//AccessID primitive.ObjectID `json:"access_id"`
}

type Room struct {
	ID   primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name string             `json:"name"`
}

type TeacherToGet struct {
	Email string `json:"email"`
}

type Response struct {
	ID      primitive.ObjectID `json:"id"`
	Name    string             `json:"name"`
	Surname string             `json:"surname"`
	Email   string             `json:"email"`
	Role    string             `json:"role"`
	Token   string             `json:"token"`
}

type LessonToGet struct {
	Groups      []Group      `json:"groups"`
	StartTime   int          `json:"startTime"`
	Subject     Subject      `json:"subject"`
	DayOfWeek   int          `json:"day_of_week"`
	TypeLesson  string       `json:"typeLesson"`
	Room        Room         `json:"room"`
	Teacher     TeacherToGet `json:"teacher"`
	TeacherName string       `json:"teacher_name"`
}
type Lesson struct {
	ID         primitive.ObjectID   `json:"id" bson:"_id,omitempty"`
	GroupIDs   []primitive.ObjectID `json:"group_ids"`
	StartTime  int                  `json:"start_time"`
	DayOfWeek  int                  `json:"day_of_week"`
	SubjectID  primitive.ObjectID   `json:"subject_id"`
	TypeLesson string               `json:"TypeLesson"`
	RoomID     primitive.ObjectID   `json:"room_id"`
	TeacherID  primitive.ObjectID   `json:"teacher_id"`
}

type Admin struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	PersonID primitive.ObjectID `json:"person_id"`
}
type User struct {
	ID      primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name    string             `json:"name"`
	Surname string             `json:"surname"`
	Group   string             `json:"group"`
	Email   string             `json:"email"`
	Role    string             `json:"role"`
}

func main() {

	// Подключение к MongoDB
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Создание маршрутизатора
	router := httprouter.New()

	router.POST("/register/admin", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		registerAdmin(w, r, client)
	})

	router.POST("/register/teacher", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		registerTeacher(w, r, client)
	})
	router.POST("/register/student", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		registerStudent(w, r, client)
	})
	router.POST("/add/group", isAuthorized(addGroup(client)))
	router.POST("/add/subject", isAuthorized(addSubject(client)))
	router.POST("/add/room", isAuthorized(addRoom(client)))
	router.POST("/add/lesson", isAuthorized(addLesson(client)))

	router.POST("/update/lesson/:id", isAuthorized(updateLesson(client)))

	router.GET("/get/lessons", isAuthorized(getAllLessons(client)))
	router.GET("/get/user", isAuthorized(getUser(client)))
	router.GET("/get/groups", isAuthorized(getAllGroups(client)))
	router.GET("/get/subjects", isAuthorized(getAllSubjects(client)))
	router.GET("/get/rooms", isAuthorized(getAllRooms(client)))
	router.GET("/get/teachers", isAuthorized(getAllTeachers(client)))

	// Обработчик POST запросов для входа пользователя
	router.POST("/login", handleLogin(client))

	// Запуск HTTP сервера
	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
func getUser(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Get user")
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized2", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized3", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" && claims.Role != "student" && claims.Role != "teacher" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if !ok {
			http.Error(w, "Unauthorized4", http.StatusUnauthorized)
			return
		}

		// Поиск пользователя в базе данных по email
		usersCollection := client.Database("test").Collection("people")
		var user User
		err = usersCollection.FindOne(context.Background(), bson.M{"email": claims.Email}).Decode(&user)
		user.Role = claims.Role
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if user.Role == "student" {

			usersCollection := client.Database("test").Collection("people")
			var person Person
			err = usersCollection.FindOne(context.Background(), bson.M{"email": claims.Email}).Decode(&person)
			if err != nil {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			var student Student
			studentCollection := client.Database("test").Collection("student")
			err = studentCollection.FindOne(context.Background(), bson.M{"personid": person.ID}).Decode(&student)
			if err != nil {
				http.Error(w, "User not found2", http.StatusUnauthorized)
				return
			}
			// Получаем коллекцию "groups"
			collection := client.Database("test").Collection("groups")

			// Выполняем запрос к коллекции для получения имени комнаты по ее ID
			var group struct {
				Name string `json:"name" bson:"name"`
			}
			err := collection.FindOne(context.Background(), bson.M{"_id": student.GroupID}).Decode(&group)
			if err != nil {
				http.Error(w, "User not found2", http.StatusUnauthorized)
				return
			}
			user.Group = group.Name
		}

		// Возврат данных о пользователе в формате JSON
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(user); err != nil {
			http.Error(w, "Failed to encode user data", http.StatusInternalServerError)
			return
		}
	}
}

func getAllTeachers(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Получение коллекции "teachers" из базы данных
		teachersCollection := client.Database("test").Collection("teacher")

		// Поиск всех документов в коллекции
		cursor, err := teachersCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get teachers", http.StatusInternalServerError)
			log.Println("Failed to get teachers:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список учителей для сохранения результатов
		var teachers []Teacher

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var teacher Teacher
			if err := cursor.Decode(&teacher); err != nil {
				http.Error(w, "Failed to decode teacher", http.StatusInternalServerError)
				log.Println("Failed to decode teacher:", err)
				return
			}
			teachers = append(teachers, teacher)
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over teachers", http.StatusInternalServerError)
			log.Println("Failed to iterate over teachers:", err)
			return
		}
		// Создание списка для хранения основных данных учителей
		var teacherBasics []struct {
			ID   primitive.ObjectID `json:"id"`
			Name string             `json:"name"`
		}

		// Получение основных данных учителей
		for _, teacher := range teachers {
			var person Person
			err := client.Database("test").Collection("people").FindOne(context.Background(), bson.M{"_id": teacher.PersonID}).Decode(&person)
			if err != nil {
				http.Error(w, "Failed to get person data", http.StatusInternalServerError)
				log.Println("Failed to get person data:", err)
				return
			}
			teacherBasics = append(teacherBasics, struct {
				ID   primitive.ObjectID `json:"id"`
				Name string             `json:"name"`
			}{
				ID:   person.ID,
				Name: person.Name,
			})
		}

		// Сериализация списка основных данных учителей в JSON
		teacherBasicsJSON, err := json.Marshal(teacherBasics)
		if err != nil {
			http.Error(w, "Failed to serialize teacher basics", http.StatusInternalServerError)
			log.Println("Failed to serialize teacher basics:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(teacherBasicsJSON)
	}
}

func getAllRooms(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Получение коллекции "subjects" из базы данных
		subjectsCollection := client.Database("test").Collection("rooms")

		// Поиск всех документов в коллекции
		cursor, err := subjectsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get subjects", http.StatusInternalServerError)
			log.Println("Failed to get subjects:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список предметов для сохранения результатов
		var subjects []Subject

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var subject Subject
			if err := cursor.Decode(&subject); err != nil {
				http.Error(w, "Failed to decode subject", http.StatusInternalServerError)
				log.Println("Failed to decode subject:", err)
				return
			}
			subjects = append(subjects, subject)
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over subjects", http.StatusInternalServerError)
			log.Println("Failed to iterate over subjects:", err)
			return
		}

		// Сериализация списка предметов в JSON
		subjectsJSON, err := json.Marshal(subjects)
		if err != nil {
			http.Error(w, "Failed to serialize subjects", http.StatusInternalServerError)
			log.Println("Failed to serialize subjects:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(subjectsJSON)
	}
}

func getAllSubjects(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Получение коллекции "subjects" из базы данных
		subjectsCollection := client.Database("test").Collection("subjects")

		// Поиск всех документов в коллекции
		cursor, err := subjectsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get subjects", http.StatusInternalServerError)
			log.Println("Failed to get subjects:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список предметов для сохранения результатов
		var subjects []Subject

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var subject Subject
			if err := cursor.Decode(&subject); err != nil {
				http.Error(w, "Failed to decode subject", http.StatusInternalServerError)
				log.Println("Failed to decode subject:", err)
				return
			}
			subjects = append(subjects, subject)
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over subjects", http.StatusInternalServerError)
			log.Println("Failed to iterate over subjects:", err)
			return
		}

		// Сериализация списка предметов в JSON
		subjectsJSON, err := json.Marshal(subjects)
		if err != nil {
			http.Error(w, "Failed to serialize subjects", http.StatusInternalServerError)
			log.Println("Failed to serialize subjects:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(subjectsJSON)
	}
}

func getAllGroups(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Получение коллекции "groups" из базы данных
		groupsCollection := client.Database("test").Collection("groups")

		// Поиск всех документов в коллекции
		cursor, err := groupsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get groups", http.StatusInternalServerError)
			log.Println("Failed to get groups:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список групп для сохранения результатов
		var groups []Group

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var group Group
			if err := cursor.Decode(&group); err != nil {
				http.Error(w, "Failed to decode group", http.StatusInternalServerError)
				log.Println("Failed to decode group:", err)
				return
			}
			groups = append(groups, group)
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over groups", http.StatusInternalServerError)
			log.Println("Failed to iterate over groups:", err)
			return
		}

		// Сериализация списка групп в JSON
		groupsJSON, err := json.Marshal(groups)
		if err != nil {
			http.Error(w, "Failed to serialize groups", http.StatusInternalServerError)
			log.Println("Failed to serialize groups:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(groupsJSON)
	}
}

func GetRoomByID(roomID primitive.ObjectID, client *mongo.Client) (string, error) {
	// Получаем коллекцию "rooms"
	collection := client.Database("test").Collection("rooms")

	// Выполняем запрос к коллекции для получения имени комнаты по ее ID
	var room struct {
		Name string `json:"name" bson:"name"`
	}
	err := collection.FindOne(context.Background(), bson.M{"_id": roomID}).Decode(&room)
	if err != nil {
		return "", err
	}

	// Возвращаем имя комнаты
	return room.Name, nil
}
func GetGroupNameByID(groupID primitive.ObjectID, client *mongo.Client) (string, error) {
	// Получаем коллекцию "groups"
	collection := client.Database("test").Collection("groups")

	// Выполняем запрос к коллекции для получения имени комнаты по ее ID
	var group struct {
		Name string `json:"name" bson:"name"`
	}
	err := collection.FindOne(context.Background(), bson.M{"_id": groupID}).Decode(&group)
	if err != nil {
		return "", err
	}

	// Возвращаем имя комнаты
	return group.Name, nil
}
func GetTeacherByID(teacherID primitive.ObjectID, client *mongo.Client) (string, error) {
	// Получаем коллекцию "teachers"
	collection := client.Database("test").Collection("teachers")

	// Выполняем запрос к коллекции для получения имени преподавателя по его ID
	var teacher struct {
		Name string `json:"name" bson:"name"`
	}
	err := collection.FindOne(context.Background(), bson.M{"_id": teacherID}).Decode(&teacher)
	if err != nil {
		return "", err
	}

	// Возвращаем имя преподавателя
	return teacher.Name, nil
}

func getAllLessons(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Проверяем авторизацию и роль
		// (ваша текущая реализация)

		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" && claims.Role != "student" && claims.Role != "teacher" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// Поиск всех уроков в коллекции
		collection := client.Database("test").Collection("lessons")
		cursor, err := collection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.Background())

		var lessons []Lesson
		// Итерируем по результатам запроса
		for cursor.Next(context.Background()) {
			var lesson Lesson
			if err := cursor.Decode(&lesson); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			lessons = append(lessons, lesson)
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Создаем срез `lessonsToGet` с начальной емкостью, равной длине среза `lessons`
		lessonsToGet := make([]LessonToGet, len(lessons))
		// Получаем имя группы по ее ID
		// Создаем пустой срез для групп

		// Проходим по каждому уроку в срезе `lessons`
		for i, lesson := range lessons {
			// Создаем срез для групп
			groups := make([]Group, len(lesson.GroupIDs))

			// Проходим по каждому идентификатору группы в уроке
			for j, groupID := range lesson.GroupIDs {
				// Получаем имя группы по ее ID
				groupName, err := GetGroupNameByID(groupID, client)
				if err != nil {
					// Обработка ошибки, если имя группы не найдено
					// Здесь можно просто присвоить пустую строку или какое-то стандартное значение
					groupName = "Unknown"
				}

				// Создаем объект Group с именем группы и добавляем его в срез
				groups[j] = Group{ID: groupID, Name: groupName}
			}
			// Создаем объект LessonToGet и заполняем его данными из соответствующего урока
			lessonsToGet[i] = LessonToGet{
				Groups:     groups,
				StartTime:  lesson.StartTime,
				DayOfWeek:  lesson.DayOfWeek,
				TypeLesson: lesson.TypeLesson,
			}

			// Получаем имя комнаты по ее ID
			roomName, err := GetRoomByID(lesson.RoomID, client)
			if err != nil {
				// Обработка ошибки, если имя комнаты не найдено
				// Здесь можно просто присвоить пустую строку или какое-то стандартное значение
				roomName = "Unknown"
			}

			// Получаем имя преподавателя по его ID
			teacherName, err := GetTeacherByID(lesson.TeacherID, client)
			if err != nil {
				// Обработка ошибки, если имя преподавателя не найдено
				// Здесь можно просто присвоить пустую строку или какое-то стандартное значение
				teacherName = "Unknown"
			}

			// Обновляем поля Room и Teacher именами в объекте LessonToGet
			lessonsToGet[i].Room.Name = roomName
			lessonsToGet[i].TeacherName = teacherName
		}
		// Кодируем результат в формат JSON и отправляем его клиенту
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(lessons); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func addGroup(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных о группе из тела запроса
		var group Group
		if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Проверка, существует ли уже группа
		collection := client.Database("test").Collection("groups")
		filter := bson.M{"name": group.Name}
		var existingGroup Group
		err = collection.FindOne(context.Background(), filter).Decode(&existingGroup)
		if err == nil {
			http.Error(w, "Group with the same name already exists", http.StatusBadRequest)
			return
		}

		// Добавление группы в базу данных
		groupsCollection := client.Database("test").Collection("groups")
		_, err = groupsCollection.InsertOne(context.Background(), group)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Ответ об успешном добавлении группы
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Group added successfully"))
	}
}

// Найти ID учителя по email
func findTeacherIDByEmail(email string, client *mongo.Client) (primitive.ObjectID, error) {
	// Поиск человека по email
	collection := client.Database("test").Collection("people")
	filter := bson.M{"email": email}
	var person Person
	err := collection.FindOne(context.Background(), filter).Decode(&person)
	if err != nil {

		return primitive.NilObjectID, err
	}

	// Поиск учителя по ID человека
	teacherCollection := client.Database("test").Collection("teacher")
	var teacher Teacher
	filter = bson.M{"personid": person.ID}
	err = teacherCollection.FindOne(context.Background(), filter).Decode(&teacher)
	if err != nil {
		return primitive.NilObjectID, err
	}

	return teacher.ID, nil
}

// Найти ID группы по имени
func findGroupIDByName(groupName string, client *mongo.Client) (primitive.ObjectID, error) {
	// Поиск группы по имени
	collection := client.Database("test").Collection("groups")
	filter := bson.M{"name": groupName}
	var group Group
	err := collection.FindOne(context.Background(), filter).Decode(&group)
	if err != nil {
		return primitive.NilObjectID, err
	}

	return group.ID, nil
}

func updateLesson(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена, срока его действия и роли пользователя
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных об уроке из тела запроса
		var lessonToGet LessonToGet
		if err := json.NewDecoder(r.Body).Decode(&lessonToGet); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Получение ID урока из URL-параметров
		lessonID := ps.ByName("id")

		// Преобразование строки в ObjectID
		objectID, err := primitive.ObjectIDFromHex(lessonID)
		if err != nil {
			http.Error(w, "Invalid lesson ID", http.StatusBadRequest)
			return
		}

		// Поиск урока в базе данных
		collection := client.Database("test").Collection("lessons")
		filter := bson.M{"_id": objectID}
		var existingLesson Lesson
		err = collection.FindOne(context.Background(), filter).Decode(&existingLesson)
		if err != nil {
			http.Error(w, "Lesson not found", http.StatusNotFound)
			return
		}

		// Обновление данных урока
		existingLesson.StartTime = lessonToGet.StartTime
		existingLesson.TypeLesson = lessonToGet.TypeLesson
		existingLesson.DayOfWeek = lessonToGet.DayOfWeek

		// Поиск в коллекции Уроки
		subjectsCollection := client.Database("test").Collection("subjects")
		var subject Subject

		err = subjectsCollection.FindOne(context.Background(), bson.M{"name": lessonToGet.Subject.Name}).Decode(&subject)
		if err != nil {
			http.Error(w, "Subject not found in subjects", http.StatusUnauthorized)
			return
		}
		existingLesson.SubjectID = subject.ID

		// Поиск в коллекции комнаты
		roomsCollection := client.Database("test").Collection("rooms")
		var room Room

		err = roomsCollection.FindOne(context.Background(), bson.M{"name": lessonToGet.Room.Name}).Decode(&room)
		if err != nil {
			http.Error(w, "room not found in rooms", http.StatusUnauthorized)
			return
		}
		existingLesson.RoomID = room.ID

		// Поиск в коллекции учителя
		existingLesson.TeacherID, err = findTeacherIDByEmail(lessonToGet.Teacher.Email, client)
		if err != nil {
			http.Error(w, "Teacher not found in Teachers", http.StatusUnauthorized)
			return
		}
		// Создаем слайс для GroupIDs с тем же размером, что и lessonToGet.Groups
		existingLesson.GroupIDs = make([]primitive.ObjectID, len(lessonToGet.Groups))

		// Находим ID группы для каждой группы в lesson.Groups
		for i, group := range lessonToGet.Groups {
			groupID, err := findGroupIDByName(group.Name, client)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error finding group ID for group %s: %v", group.Name, err), http.StatusInternalServerError)
				return
			}
			existingLesson.GroupIDs[i] = groupID
		}

		// Обновление урока в базе данных
		_, err = collection.ReplaceOne(context.Background(), filter, existingLesson)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Ответ об успешном обновлении урока
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Lesson updated successfully"))
	}
}

func addLesson(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных об уроке из тела запроса
		var lessonToGet LessonToGet
		if err := json.NewDecoder(r.Body).Decode(&lessonToGet); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		//
		var lesson Lesson
		lesson.ID = primitive.NewObjectID()
		lesson.StartTime = lessonToGet.StartTime
		lesson.TypeLesson = lessonToGet.TypeLesson
		lesson.DayOfWeek = lessonToGet.DayOfWeek

		// Поиск в коллекции Уроки
		subjectsCollection := client.Database("test").Collection("subjects")
		var subject Subject

		err = subjectsCollection.FindOne(context.Background(), bson.M{"name": lessonToGet.Subject.Name}).Decode(&subject)
		if err != nil {
			http.Error(w, "Subject not found in subjects", http.StatusUnauthorized)
			return
		}
		lesson.SubjectID = subject.ID

		// Поиск в коллекции комнаты
		roomsCollection := client.Database("test").Collection("rooms")
		var room Room

		err = roomsCollection.FindOne(context.Background(), bson.M{"name": lessonToGet.Room.Name}).Decode(&room)
		if err != nil {
			http.Error(w, "room not found in rooms", http.StatusUnauthorized)
			return
		}
		lesson.RoomID = room.ID

		// Поиск в коллекции учителя
		lesson.TeacherID, err = findTeacherIDByEmail(lessonToGet.Teacher.Email, client)
		if err != nil {
			http.Error(w, "Teacher not found in Teachers", http.StatusUnauthorized)
			return
		}
		// Создаем слайс для GroupIDs с тем же размером, что и lessonToGet.Groups
		lesson.GroupIDs = make([]primitive.ObjectID, len(lessonToGet.Groups))

		// Находим ID группы для каждой группы в lesson.Groups
		for i, group := range lessonToGet.Groups {
			groupID, err := findGroupIDByName(group.Name, client)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error finding group ID for group %s: %v", group.Name, err), http.StatusInternalServerError)
				return
			}
			lesson.GroupIDs[i] = groupID
		}

		// Проверка, существует ли уже lesson
		collection := client.Database("test").Collection("lessons")
		filter := bson.M{"name": subject.Name}
		var existingLesson Lesson
		err = collection.FindOne(context.Background(), filter).Decode(&existingLesson)
		if err == nil {
			http.Error(w, "Lesson with the same name already exists", http.StatusBadRequest)
			return
		}

		// Добавление lesson в базу данных
		_, err = collection.InsertOne(context.Background(), lesson)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Ответ об успешном добавлении группы
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Lesson added successfully"))
	}
}

// Добавление урока
func addSubject(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных о группе из тела запроса
		var subject Subject
		if err := json.NewDecoder(r.Body).Decode(&subject); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Проверка, существует ли уже урок
		collection := client.Database("test").Collection("subjects")
		filter := bson.M{"name": subject.Name}
		var existingSubject Subject
		err = collection.FindOne(context.Background(), filter).Decode(&existingSubject)
		if err == nil {
			http.Error(w, "Subject with the same name already exists", http.StatusBadRequest)
			return
		}

		// Добавление группы в базу данных
		subjectsCollection := client.Database("test").Collection("subjects")
		_, err = subjectsCollection.InsertOne(context.Background(), subject)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Ответ об успешном добавлении группы
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Subject added successfully"))
	}
}

// Добавление Комнаты
func addRoom(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных о группе из тела запроса
		var room Room
		if err := json.NewDecoder(r.Body).Decode(&room); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Проверка, существует ли уже room
		collection := client.Database("test").Collection("rooms")
		filter := bson.M{"name": room.Name}
		var existingRoom Room
		err = collection.FindOne(context.Background(), filter).Decode(&existingRoom)
		if err == nil {
			http.Error(w, "Room with the same name already exists", http.StatusBadRequest)
			return
		}

		// Добавление room в базу данных
		roomCollection := client.Database("test").Collection("rooms")
		_, err = roomCollection.InsertOne(context.Background(), room)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Ответ об успешном добавлении группы
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Room added successfully"))
	}
}

// Логин
func handleLogin(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Декодирование JSON данных из тела запроса

		fmt.Println("login get")
		var loginInfo struct {
			Email  string `json:"email"`
			Passwd string `json:"passwd"`
		}
		err := json.NewDecoder(r.Body).Decode(&loginInfo)
		fmt.Println(err)
		fmt.Println(loginInfo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Поиск пользователя в базе данных
		var role string

		// Поиск в коллекции людей
		peopleCollection := client.Database("test").Collection("people")
		var person Person
		err = peopleCollection.FindOne(context.Background(), bson.M{"email": loginInfo.Email}).Decode(&person)
		if err != nil {
			http.Error(w, "User not found1", http.StatusUnauthorized)
			return
		}
		// Проверка пароля
		err = bcrypt.CompareHashAndPassword([]byte(person.Passwd), []byte(loginInfo.Passwd))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Определение роли пользователя и получение PersonID

		var admin Admin
		adminCollection := client.Database("test").Collection("admin")
		err = adminCollection.FindOne(context.Background(), bson.M{"personid": person.ID}).Decode(&admin)

		if err != nil {
			var teacher Teacher
			teacherCollection := client.Database("test").Collection("teacher")
			err := teacherCollection.FindOne(context.Background(), bson.M{"personid": person.ID}).Decode(&teacher)
			if err != nil {

				var student Student
				studentCollection := client.Database("test").Collection("student")
				err = studentCollection.FindOne(context.Background(), bson.M{"personid": person.ID}).Decode(&student)
				if err != nil {
					http.Error(w, "User not found2", http.StatusUnauthorized)
					return
				}
				role = "student"
			} else {
				role = "teacher"
			}
		} else {
			role = "admin"
		}

		// Генерация JWT токена
		expirationTime := time.Now().Add(15 * time.Minute) // Время жизни токена
		claims := &Claims{
			Role:  role,
			Email: person.Email,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Создаем экземпляр структуры Response

		response := Response{
			ID:      person.ID,
			Name:    person.Name,
			Surname: person.Surname,
			Email:   person.Email,
			Role:    role,
			Token:   tokenString,
		}
		// Сериализуем структуру в JSON
		responseJSON, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
			return
		}

		// Устанавливаем заголовок Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправляем JSON в качестве ответа
		w.Write(responseJSON)
	}
}

// Middleware для проверки токена
func isAuthorized(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Проверка наличия токена в заголовке авторизации
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Продолжение выполнения запроса
		next(w, r, ps)
	}
}

// Регистрация учителя
func registerTeacher(w http.ResponseWriter, r *http.Request, client *mongo.Client) {

	// Проверка авторизации и роли
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Проверка токена
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Проверка срока действия токена
	if !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Проверка роли
	claims, ok := token.Claims.(*Claims)
	if !ok || claims.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var person Person
	person = Person{ID: primitive.NewObjectID()}
	err = json.NewDecoder(r.Body).Decode(&person)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Проверка, существует ли уже человек с таким email
	collection := client.Database("test").Collection("people")
	filter := bson.M{"email": person.Email}
	var existingPerson Person
	err = collection.FindOne(context.Background(), filter).Decode(&existingPerson)
	if err == nil {
		http.Error(w, "Person with the same email already exists", http.StatusBadRequest)
		return
	}

	// Хеширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(person.Passwd), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	person.Passwd = string(hashedPassword)

	// Сохранение данных в базе данных
	_, err = collection.InsertOne(context.Background(), person)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Создание записи учителя
	teacher := Teacher{PersonID: person.ID}
	collection = client.Database("test").Collection("teacher")
	_, err = collection.InsertOne(context.Background(), teacher)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправка успешного ответа
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Teacher registered successfully"))
}

// Регистрация Студента
func registerStudent(w http.ResponseWriter, r *http.Request, client *mongo.Client) {

	// Проверка авторизации и роли
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Проверка токена
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Проверка срока действия токена
	if !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Проверка роли
	claims, ok := token.Claims.(*Claims)
	if !ok || claims.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var person StudentToGet
	person = StudentToGet{ID: primitive.NewObjectID()}
	err = json.NewDecoder(r.Body).Decode(&person)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Проверка, существует ли уже человек с таким email
	collection := client.Database("test").Collection("people")
	filter := bson.M{"email": person.Email}
	var existingPerson Person
	err = collection.FindOne(context.Background(), filter).Decode(&existingPerson)
	if err == nil {
		http.Error(w, "Person with the same email already exists", http.StatusBadRequest)
		return
	}

	// Хеширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(person.Passwd), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	person.Passwd = string(hashedPassword)

	// Сохранение данных в базе данных
	_, err = collection.InsertOne(context.Background(), person)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	collection = client.Database("test").Collection("student")
	student := Student{PersonID: person.ID, GroupID: person.GroupID}

	_, err = collection.InsertOne(context.Background(), student)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправка успешного ответа
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Student registered successfully"))

}

// Регистрация админа
func registerAdmin(w http.ResponseWriter, r *http.Request, client *mongo.Client) {
	var person Person
	person = Person{ID: primitive.NewObjectID()}
	err := json.NewDecoder(r.Body).Decode(&person)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Проверка, существует ли уже человек с таким email
	collection := client.Database("test").Collection("people")
	filter := bson.M{"email": person.Email}
	var existingPerson Person
	err = collection.FindOne(context.Background(), filter).Decode(&existingPerson)
	if err == nil {
		http.Error(w, "Person with the same email already exists", http.StatusBadRequest)
		return
	}

	// Хеширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(person.Passwd), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	person.Passwd = string(hashedPassword)

	// Сохранение данных в базе данных
	_, err = collection.InsertOne(context.Background(), person)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	collection = client.Database("test").Collection("admin")
	// Создание записи админа
	admin := Admin{PersonID: person.ID}
	_, err = collection.InsertOne(context.Background(), admin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправка успешного ответа
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Admin registered successfully"))
}
