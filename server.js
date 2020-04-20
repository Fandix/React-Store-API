/*
    name : server
    Date : 2020/04/14
    description : 對於登陸用戶的帳號與密碼進行檢測
*/

const path = require("path");
const fs = require("fs");
const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const jwt = require("jsonwebtoken");

server.use(jsonServer.bodyParser);
server.use(middlewares)

//=====================================================================//

/*
    Date : 2020/04/14
    Description : 取得users.json中的用戶帳號密碼訊息
*/
getUserDb = () => {
   return JSON.parse(fs.readFileSync(path.join(__dirname,"users.json"),"UTF-8"))
};

//=====================================================================//

/*
    Date : 2020/04/14
    Description : 判斷輸入的email與password是否等於users.json中的用戶帳號密碼(用戶認證)
*/
const isAuthenticated = ({email,password}) => {
  return(
    getUserDb().users.findIndex(
      user => user.email === email && user.password === password
      ) !== -1
  ) ;
};

//=====================================================================//

/*
    Date : 2020/04/18
    Description : 判斷輸入的信箱是否已存在於users.json中
*/
const isExist = (email) => {
  return(
    getUserDb().users.findIndex(
      user => user.email === email) !== -1
  ) ;
};

//=====================================================================//

/*
    Date : 2020/04/14
    Description : 利用輸入的參數生成jwt中的payload
*/
const SECRET = "123456astwearwadsaf";
const expiresIn = "1h"
const createToken = (payload) => {
  return jwt.sign(payload,SECRET,{expiresIn})
};

//=====================================================================//

/*
    Date : 2020/04/14
    Description : 若用戶認證完成，將JWT碼post到JSON-Server中
*/
server.post("/auth/login",(req,res) => {

  //Step 1:取得輸入的email與password
  const {email,password} = req.body;

  //Step 2:判斷輸入的email與password是否存在於users.json中的數據(用戶認證)
  if(isAuthenticated({email,password}))
  {
    //Step 3:在users.json中獲取準確的用戶資料(email,password,nickname,type,id)
    const user = getUserDb().users.find(
        u => u.email === email && u.password === password
    );

    //Step 4:取得nickname與type
    const {nickname,type} = user;

    //Step 5:將nickname與type輸入function中產生JWT Token
    const JwToKen = createToken({nickname,type,email});
    return res.status(200).json(JwToKen);
  }
  else
  {
    //帳戶認證失敗
    const status = 401;
    const message = "Incorrect email or password";
    return res.status(status).json({status,message})
  }
})

//=====================================================================//

/*
    Date : 2020/04/18
    Description : 用戶註冊處理
*/
server.post("/auth/register",(req,res) => {

  //Step 1:取得用戶註冊資訊
  const {email,password,nickname,type} = req.body;

  //Step 2:確認用戶註冊的內容是否已經存在於users.json
  if(isExist(email))
  {
    const status = 401;
    const message = "Email and Password already exist";
    return res.status(status).json({status,message});
  }

  //Step 3:若用戶註冊的內容尚未存在於users.json中則將用戶註冊資料存入users,json中
  //Step 3-1 : 讀取users.json文件
  fs.readFile(path.join(__dirname,"users.json"),(err,_data) => {
    if(err)
    {
      const status = 401;
      const message = err;
      return res.status(status).json({status,message});
    }

    //Step 3-2 : 將json格式轉為Object
    const data = JSON.parse(_data.toString());

    //Step 3-3 : 取得上一個數據的id數值，並把本次新增的資料id = 上一筆id + 1 
    const last_item_id = data.users[data.users.length - 1].id; //所有data中的n-1的data裡面的id
    data.users.push({id:last_item_id+1,email,password,nickname,type});

    //Step 3-4 : 利用fs.write Method將新註冊用戶的資訊寫入user.json文件中
    fs.writeFile(path.join(__dirname,"users.json"),JSON.stringify(data),(err,result) => {
      if(err)
      {
        const status = 401;
        const message = err;
        return res.status(status).json({status,message});
      }
    });
  });

  //Strp 4: 生成新用戶的JWToken
  const JwToKen = createToken({nickname,type,email});
  res.status(200).json(JwToKen);
});

//=====================================================================//

/*
    Date : 2020/04/18
    Description : 驗證JWToken
*/

const verifyToken = (token) => {
  return jwt.verify(token,SECRET,(err,decode) => 
    decode !== undefined? decode : err
  );
};

//=====================================================================//

/*
    Date : 2020/04/18
    Description : 用戶權限處理 => 控制購物車組件是否顯示
*/
server.use("/carts",(req,res,next) => {

  //Step 1 : 判斷是否有取得JWToken中的authoration
  if(req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer')
  {
    const status = 401;
    const message = "Error in authorization format";
    return res.status(status).json({status,message});
  }

  //Step 2 : 取得JWToken
  try 
  {
    //Step 2-1 : 將JWToken傳入verifyToken function中確認是否符合
     const verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);
     if(verifyTokenResult instanceof Error)
     {
      const status = 401;
      const message = "Access token not provided";
      return res.status(status).json({status,message});
     }
     next();
  } 
  catch (error) 
  {
      const status = 401;
      const message = "Error token is revoked";
      return res.status(status).json({status,message});
  }

});

//=====================================================================//

server.use(router)
server.listen(3003, () => {
  console.log('JSON Server is running')
})