{-# LANGUAGE DoAndIfThenElse #-}
{-# LANGUAGE OverloadedStrings #-}
module Web.Spock.Auth
    ( -- * Initialisation helpers
      authSessCfg, AuthCfg (..)
      -- * Handeling custom session data
    , writeSessionData, readSessionData, modifySessionData
      -- * Access control
    , VisitorSession, NoAccessReason (..)
    , NoAccessHandler, LoadUserFun, CheckRightsFun, UserRights
    , markAsLoggedIn
    , markAsGuest
    , userRoute
    )
where

import Web.Spock

import Control.Applicative
import Data.Time.Clock
import qualified Network.HTTP.Types as Http
import qualified Data.Text as T

-- | Configuration
data AuthCfg sess
   = AuthCfg
   { ac_sessionTTL :: NominalDiffTime
   , ac_emptySession :: sess
   }

-- | Assign the current session roles/permission, eg. admin or user
type UserRights = T.Text

-- | Describes why access was denied to a user
data NoAccessReason
   = NotEnoughRights
   | NotLoggedIn
   | NotValidUser
   deriving (Show, Eq, Read, Enum)

-- | Define what happens to non-authorized requests
type NoAccessHandler conn sess userId st =
    NoAccessReason -> SpockAction conn (VisitorSession sess userId) st ()

-- | How should a session be transformed into a user? Can access the database using 'runQuery'
type LoadUserFun conn sess userId st user =
    userId -> SpockAction conn (VisitorSession sess userId) st (Maybe user)

-- | What rights does the current user have? Can access the database using 'runQuery'
type CheckRightsFun conn sess userId st user =
    user -> [UserRights] -> SpockAction conn (VisitorSession sess userId) st Bool

data SessionType userId
   = GuestSession
   | UserSession userId
   deriving (Show, Eq)

data VisitorSession sess userId
   = VisitorSession
   { vs_type :: SessionType userId
   , vs_data :: sess
   }
   deriving (Show, Eq)

-- | Plug this into the 'spock' function to create SessionCfg
authSessCfg :: AuthCfg sess -> SessionCfg (VisitorSession sess userId)
authSessCfg authCfg =
    SessionCfg
    { sc_cookieName = "spocksession"
    , sc_sessionTTL = ac_sessionTTL authCfg
    , sc_sessionIdEntropy = 42
    , sc_emptySession = VisitorSession GuestSession (ac_emptySession authCfg)
    }

-- | Mark current visitor as logged in
markAsLoggedIn :: userId -> SpockAction conn (VisitorSession sess userId) st ()
markAsLoggedIn userId =
    modifySession (\oldData -> oldData { vs_type = (UserSession userId) })

-- | Mark current visitor as guest
markAsGuest :: SpockAction conn (VisitorSession sess userId) st ()
markAsGuest =
    modifySession (\oldData -> oldData { vs_type = GuestSession })

-- | Replacement for 'readSession'
readSessionData :: SpockAction conn (VisitorSession sess userId) st sess
readSessionData =
    vs_data <$> readSession

-- | Replacement for 'modifySession'
modifySessionData :: (sess -> sess) -> SpockAction conn (VisitorSession sess userId) st ()
modifySessionData f =
    modifySession (\oldData -> oldData { vs_data = f (vs_data oldData) })

-- | Replacement for 'writeSession'
writeSessionData :: sess -> SpockAction conn (VisitorSession sess userId) st ()
writeSessionData v =
    modifySessionData (const v)

-- | Before the request is performed, you can check if the signed in user has permissions to
-- view the contents of the request. You may want to define a helper function that
-- proxies this function to not pass around 'NoAccessHandler', 'LoadUserFun' and 'CheckRightsFun'
-- all the time.
-- Example:
--
-- > type MyWebMonad a = SpockAction Connection (VisitorSession () UserId) () a
-- > newtype MyUser = MyUser { unMyUser :: T.Text }
-- >
-- > http403 msg =
-- >    do status Http.status403
-- >       text (show msg)
-- >
-- > login :: Http.StdMethod
-- >       -> [UserRights]
-- >       -> RoutePattern
-- >       -> (MyUser -> MyWebMonad ())
-- >       -> MyWebMonad ()
-- > login =
-- >     userRoute http403 myLoadUser myCheckRights
--
userRoute :: NoAccessHandler conn sess userId st
          -> LoadUserFun conn sess userId st user
          -> CheckRightsFun conn sess userId st user
          -> Http.StdMethod
          -> [UserRights]
          -> RoutePattern
          -> (user -> SpockAction conn (VisitorSession sess userId) st ())
          -> SpockM conn (VisitorSession sess userId) st ()
userRoute noAccessHandler loadUser checkRights reqTy requiredRights route action =
    addroute reqTy route $
    do sessData <- readSession
       case vs_type sessData of
         GuestSession ->
             noAccessHandler NotLoggedIn
         UserSession userId ->
             do mUser <- loadUser userId
                case mUser of
                  Nothing ->
                      noAccessHandler NotValidUser
                  Just user ->
                      do isOk <- checkRights user requiredRights
                         if isOk
                         then action user
                         else noAccessHandler NotEnoughRights
