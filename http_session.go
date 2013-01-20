package http_session
import (
  "fmt"
  "time"
  "math/rand"
  "io"
  "crypto/md5"
  "strings"
  "net/http"
  "strconv"
  "os"
  "io/ioutil"
)


/*
 * Структура сессии
 */
type session struct{
  path string; // Путь к файлам
  name string; // Имя сессии
  time int64; // Время хранения сессии
  limit int32; // Максимальное количество сессий
  value map[int32]string // ОЗУ значение сессии
  time_session map[int32]int64 // ОЗУ время начало сессии
  hash_session map[int32]string // ОЗУ проверка сессии
  hash_file_session map[int32]string // Файловая версия хеш
  time_file_session map[int32]int64 //Файловая сессия время
}


/*
 * Извне инициализация сессии
 */
func Init(name string, limit int32, time int64, file ... string) (*session, error){
  type_session := new(session)
  type_session.name = name
  type_session.time = time
  type_session.limit = limit
  if len(file) == 1 { // Файловый режим
    os.Mkdir(file[0], 0777)
    files,err_dir_read := ioutil.ReadDir(file[0])
    if err_dir_read != nil {
      return type_session, err_dir_read
    }
    type_session.hash_file_session = make(map[int32]string,limit)
    type_session.time_file_session = make(map[int32]int64,limit)
    for i := 0; i<len(files); i++ {
      if files[i].IsDir() == false && len(strings.Split((files[i].Name()), "_")) == 2 {
  i32,_ := strconv.ParseInt((strings.Split((files[i].Name()), "_")[1]),10,32)
	ii32 := int32(i32)
	if ii32 < limit {
	  type_session.hash_file_session[ii32] = strings.Split((files[i].Name()), "_")[0]
	  type_session.time_file_session[ii32] = (files[i].ModTime()).Unix()
	}
      }
    }
    type_session.path = file[0]
    return type_session, nil
  } // ОЗУшный режим
  type_session.path = ""
  type_session.value = make(map[int32]string,limit)
  type_session.time_session = make(map[int32]int64, limit)
  type_session.hash_session = make(map[int32]string,limit)
  return type_session, nil
}


/*
 * Извне установка сессии
 */
func (s *session) Set (name string, value string, w http.ResponseWriter, r* http.Request) bool{
  if s.path == "" {
    cookie_r, err_r := r.Cookie(s.name)
    if err_r == nil {
      if len(strings.Split(cookie_r.Value, "_")) == 2 {
	r_md5 := (strings.Split(cookie_r.Value, "_"))[0]
	r_32, _ := strconv.ParseInt(((strings.Split(cookie_r.Value, "_"))[1]), 10, 32)
	r_id := int32(r_32)
	if s.hash_session[r_id] == r_md5 && s.time_session[r_id] + s.time > (time.Now()).Unix(){
	  s.time_session[r_id] = (time.Now()).Unix()
	  parseSetSessionOzy(s, r_id, name, value)
	  return true
	}
      }
    }
    if len(w.Header()[http.CanonicalHeaderKey("set-cookie")]) != 0 {
      cookie_w := w.Header()[http.CanonicalHeaderKey("set-cookie")]
      for i := 0; i < len(cookie_w); i++ {
	if strings.Index(cookie_w[i], s.name+"=") == 0 && len(strings.Split((strings.Split(cookie_w[i], s.name+"="))[1], "_")) == 2 {
	  w_md5 := (strings.Split((strings.Split(cookie_w[i], s.name+"="))[1], "_"))[0]
	  w_32, _ := strconv.ParseInt((strings.Split((strings.Split(cookie_w[i], s.name+"="))[1], "_"))[1], 10, 32)
	  w_id := int32(w_32)
	  if s.hash_session[w_id] == w_md5 && s.time_session[w_id] + s.time > (time.Now()).Unix(){
	    s.time_session[w_id] = (time.Now()).Unix()
	    parseSetSessionOzy(s, w_id, name, value)
	    return true
	  }
	}
      }
    }
    t_now := (time.Now()).Unix() - s.time
    var i int32 = 0
    for ; i < s.limit; i++ {
      if s.time_session[i] < t_now {
	s.time_session[i] = t_now + s.time
	s.hash_session[i] = md5_rand()
	parseSetSessionOzy(s, i, name, value)
	http.SetCookie(w, &http.Cookie{Name:s.name, Value:s.hash_session[i]+"_"+fmt.Sprint(i)})
	return true
      }
    }
    return false
  }
  // Файловая версия
  cookie_r, err_r := r.Cookie(s.name)
  if err_r == nil {
    if len(strings.Split(cookie_r.Value, "_")) == 2 {
      r_md5 := (strings.Split(cookie_r.Value, "_"))[0]
      r_32, _ := strconv.ParseInt(((strings.Split(cookie_r.Value, "_"))[1]), 10, 32)
      r_id := int32(r_32)
      if s.hash_file_session[r_id] == r_md5 && s.time_file_session[r_id] + s.time > (time.Now()).Unix(){
	if parseSetSessionFile(s, cookie_r.Value, name, value) == true {
	  s.time_file_session[r_id] = (time.Now()).Unix()
	  return true
	}
      }
    }
  }
  if len(w.Header()[http.CanonicalHeaderKey("set-cookie")]) != 0 {
    cookie_w := w.Header()[http.CanonicalHeaderKey("set-cookie")]
    for i := 0; i < len(cookie_w); i++ {
      if strings.Index(cookie_w[i], s.name+"=") == 0 && len(strings.Split((strings.Split(cookie_w[i], s.name+"="))[1], "_")) == 2 {
	w_md5 := (strings.Split((strings.Split(cookie_w[i], s.name+"="))[1], "_"))[0]
	w_32, _ := strconv.ParseInt((strings.Split((strings.Split(cookie_w[i], s.name+"="))[1], "_"))[1], 10, 32)
	w_id := int32(w_32)
	if s.hash_file_session[w_id] == w_md5 && s.time_file_session[w_id] + s.time > (time.Now()).Unix(){
	  if parseSetSessionFile(s, (strings.Split(cookie_w[i], s.name+"="))[1], name, value) == true {
	    s.time_file_session[w_id] = (time.Now()).Unix()
	    return true
	  }
	}
      }
    }
  }
  t_now := (time.Now()).Unix() - s.time
  var i int32 = 0
  for ; i < s.limit; i++ {
    if s.time_file_session[i] < t_now {
      old := s.path+s.hash_file_session[i]+"_"+fmt.Sprint(i)
      _md5 := md5_rand()
      if os.Rename(old, s.path+_md5+"_"+fmt.Sprint(i)) != nil {
	_, err := os.Create(s.path+_md5+"_"+fmt.Sprint(i))
	if err != nil {
	  return false
	}
      }else{
	file, err_open := os.OpenFile(s.path+_md5+"_"+fmt.Sprint(i), os.O_WRONLY, 0660)
	if err_open != nil {
	  return false
	}
	file.Truncate(0)
	file.Close()
      }
      s.time_file_session[i] = t_now + s.time
      s.hash_file_session[i] = _md5
      if parseSetSessionFile(s, s.hash_file_session[i]+"_"+fmt.Sprint(i), name, value) == true {
	http.SetCookie(w, &http.Cookie{Name:s.name, Value:s.hash_file_session[i]+"_"+fmt.Sprint(i)})
	return true
      }
    }
  }
  return false
}





/*
 * Извне получение сессии
 */
func (s *session) Get (name string, r *http.Request) string{
  if s.path == "" {
    cookie_r, err_r := r.Cookie(s.name)
    if err_r == nil {
      if len(strings.Split(cookie_r.Value, "_")) == 2 {
	r_md5 := (strings.Split(cookie_r.Value, "_"))[0]
	r_32, _ := strconv.ParseInt(((strings.Split(cookie_r.Value, "_"))[1]), 10, 32)
	r_id := int32(r_32)
	if s.hash_session[r_id] == r_md5 && s.time_session[r_id] + s.time > (time.Now()).Unix(){
	  s.time_session[r_id] = (time.Now()).Unix()
	  return strings.Replace(parseGetSessionOzy(s.value[r_id], name), "\\;\\", ";", -1)
	}
      }
    }
    return ""
  }
  cookie_r, err_r := r.Cookie(s.name)
  if err_r == nil {
    if len(strings.Split(cookie_r.Value, "_")) == 2 {
      r_md5 := (strings.Split(cookie_r.Value, "_"))[0]
      r_32, _ := strconv.ParseInt(((strings.Split(cookie_r.Value, "_"))[1]), 10, 32)
      r_id := int32(r_32)
      if s.hash_file_session[r_id] == r_md5 && s.time_file_session[r_id] + s.time > (time.Now()).Unix(){
	file, err_open := os.OpenFile(s.path+cookie_r.Value, os.O_RDONLY, 0660)
	if err_open != nil {
	  return ""
	}
	file_info, _ := file.Stat()
	bytes := make([]byte,file_info.Size())
	file.Read(bytes)
	str := strings.TrimRight((strings.TrimLeft(string(bytes), " ")), " ")
	file.Close();
	return parseGetSessionOzy(str, name)
      }
    }
  }
  return ""
}


/*
 * Установка сессии в ОЗУ, если path = ""
 */
func parseSetSessionOzy(s *session, id int32, name string, value string){
  if value != "" {
    if strings.Index(s.value[id], name) == -1 {
      s.value[id] += ";"+name+"="+strings.Replace(value, ";", "\\;\\", -1);
    }else{
      getvalue := strings.Split(s.value[id], ";"+name+"="+parseGetSessionOzy(s.value[id], name))
      if len(getvalue) > 1 {
      s.value[id] = getvalue[0]+";"+name+"="+strings.Replace(value, ";", "\\;\\", -1)+getvalue[1]
      }else{
	s.value[id] = getvalue[0]
      }
    }
  }else{
    if strings.Index(s.value[id], ";"+name+"=") != -1 {
      getvalue := strings.Split(s.value[id], ";"+name+"="+parseGetSessionOzy(s.value[id], name))
      if len(getvalue) > 1 {
      s.value[id] = getvalue[0]+getvalue[1]
      }else{
	s.value[id] = getvalue[0]
      }
    }
  }
}


/*
 * Установка значений в файле
 */
func parseSetSessionFile(s *session, cookie_value string, name string, value string) bool {
  file, err_open := os.OpenFile(s.path+cookie_value, os.O_RDONLY, 0660)
  if err_open != nil {
    return false
  }
  file_info, _ := file.Stat()
  bytes := make([]byte,file_info.Size())
  file.Read(bytes)
  str := strings.TrimRight((strings.TrimLeft(string(bytes), " ")), " ")
  file.Close()
  if value != "" {
    if strings.Index(str, name) == -1 {
      str += ";"+name+"="+strings.Replace(value, ";", "\\;\\", -1);
    }else{
      getvalue := strings.Split(str, ";"+name+"="+parseGetSessionOzy(str, name))
      if len(getvalue)>1 {
      str = getvalue[0]+";"+name+"="+strings.Replace(value, ";", "\\;\\", -1)+getvalue[1]
      }else{
	str = getvalue[0]+";"+name+"="+strings.Replace(value, ";", "\\;\\", -1)
      }
    }
  }else{
    if strings.Index(str, ";"+name+"=") != -1 {
      getvalue := strings.Split(str, ";"+name+"="+parseGetSessionOzy(str, name))
      if len(getvalue)>1 {
      str = getvalue[0]+getvalue[1]
      }else{
	str = getvalue[0]
      }
    }
  }
  file, err_open = os.OpenFile(s.path+cookie_value, os.O_WRONLY, 0660)
  if err_open != nil {
    return false
  }
  file.Truncate(0)
  file.WriteString(str)
  file.Close()
  return true
}


/*
 * Извне удаление сессии
 */
func (s *session) Remove(r *http.Request) {
  if s.path == "" {
    cookie_r, err_r := r.Cookie(s.name)
    if err_r == nil {
      r_md5 := (strings.Split(cookie_r.Value, "_"))[0]
      if len(strings.Split(cookie_r.Value, "_")) == 2 {
	r_32, _ := strconv.ParseInt(((strings.Split(cookie_r.Value, "_"))[1]), 10, 32)
	r_id := int32(r_32)
	if s.hash_session[r_id] == r_md5 && s.time_session[r_id] + s.time > (time.Now()).Unix(){
	  s.time_session[r_id] = 0
	  s.hash_session[r_id] = ""
	  s.value[r_id] = ""
	}
      }
    }
    return
  }
  cookie_r, err_r := r.Cookie(s.name)
    if err_r == nil {
      r_md5 := (strings.Split(cookie_r.Value, "_"))[0]
      if len(strings.Split(cookie_r.Value, "_")) == 2 {
	r_32, _ := strconv.ParseInt(((strings.Split(cookie_r.Value, "_"))[1]), 10, 32)
	r_id := int32(r_32)
	if s.hash_file_session[r_id] == r_md5 && s.time_file_session[r_id] + s.time > (time.Now()).Unix(){
	  s.time_file_session[r_id] = 0
	}
      }
    }
}


/*
 * Поиск сессии в ОЗУ, если path = ""
 */
func parseGetSessionOzy(str string, name string) string{
  if len(strings.Split(str, ";"+name+"=")) == 1 {
    return ""
  }
  r := strings.Split((strings.Split(str, ";"+name+"="))[1], "\\;\\");
  new_string := ""
  for i := 0; i<len(r); i++ {
    if strings.Index(r[i], ";") == -1 {
      if i == len(r) -1 {
	new_string += r[i]
	break
      }
      new_string += r[i]+"\\;\\"
    }else{
      new_string += (strings.Split(r[i],";"))[0]
      break
    };
  }
  return new_string
}


/*
 * Случайный md5-хеш
 */
func md5_rand() string{
  md5_ := md5.New()
  io.WriteString(md5_, fmt.Sprint(rand.Int63n(int64((time.Now()).Unix())+int64((time.Now()).Nanosecond()))))
  return fmt.Sprintf("%x", md5_.Sum(nil))
}
