{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
module Main (main) where

import Prelude ()
import Prelude.Compat
import Control.Applicative        (many, optional, some, (<|>))
import Control.Lens
       (at, forOf_, makeLenses, (%~), (&), (.~), (^.), _Wrapped)
import Control.Monad              (void)
import Control.Monad.Catch        (catch)
import Control.Monad.Catch        (throwM)
import Control.Monad.CryptoRandom
       (CRand, GenError, MonadCRandomR (..), evalCRand, newGenIO)
import Control.Monad.IO.Class     (MonadIO (..))
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Crypto.Random.DRBG         (HmacDRBG)
import Data.Aeson
       (FromJSON (..), FromJSON1 (..), Value (..), parseJSON1, withObject,
       (.!=), (.:), (.:?))
import Data.Aeson.Types           (typeMismatch)
import Data.Bifunctor             (bimap)
import Data.Char                  (isAlpha)
import Data.Foldable              (for_)
import Data.Functor.Identity      (Identity)
import Data.HashMap.Strict        (HashMap)
import Data.List                  (isSuffixOf, sort)
import Data.Maybe                 (fromMaybe)
import Data.Monoid                ((<>))
import Data.Proxy                 (Proxy (..))
import Data.Text                  (Text)
import Data.Text.Lens             (unpacked)
import Data.Yaml                  (decodeEither', encode)
import System.Directory           (getDirectoryContents)
import System.Environment         (getEnv, getEnvironment)
import System.Exit                (ExitCode (..), exitFailure)
import System.Exit.Lens           (_ExitFailure)
import System.IO                  (stderr)
import System.Process             (createProcess, proc, waitForProcess)


import Text.Regex.Applicative.Text (RE', psym, replace, sym)

import Distribution.PackageDescription       (GenericPackageDescription (..))
import Distribution.Verbosity                (normal)

#if MIN_VERSION_Cabal(2,0,0)
import Distribution.Types.UnqualComponentName (unUnqualComponentName)
import Distribution.PackageDescription.Parse (readGenericPackageDescription)
#else
import Distribution.PackageDescription.Parse (readPackageDescription)
#endif

import qualified Data.ByteString           as BS
import qualified Data.HashMap.Strict       as HM
import qualified Data.Text                 as T
import qualified Data.Text.IO              as T
import qualified Options.Applicative       as O
import qualified System.Process            as Process
import qualified System.Process.ByteString as ProcessBS

type EnvName = Text
type Env = HashMap Text EnvValue

data EnvValue
    = EVPublic Text
    | EVSecret Text
    deriving (Show)

instance FromJSON EnvValue where
    parseJSON (String t) = pure $ EVPublic t
    parseJSON (Object o)
        | HM.size o == 1 = EVSecret <$> o .: "secret"
        | otherwise      = fail "Other keys than secret"
    parseJSON v = typeMismatch "EnvValue" v

-------------------------------------------------------------------------------
-- Error
-------------------------------------------------------------------------------

type Tajna = ExceptT TajnaError IO

data TajnaError
    = InvalidYaml FilePath String
    | UnknownSecret Text
    | NoCabalFile
    | NoExeInCabal FilePath
    deriving (Show)

-------------------------------------------------------------------------------
-- Config
-------------------------------------------------------------------------------

data Config f = Config
    { _configDefEnv  :: !(f EnvName)
    , _configRtsOpts :: !Text
    , _configEnvs    :: !(HashMap EnvName Env)
    }

makeLenses ''Config

instance FromJSON1 f => FromJSON (Config f) where
    parseJSON = withObject "Confog" $ \obj -> Config
        <$> fmap lower1 (obj .: "default")
        <*> obj .:? "rtsopts" .!= ""
        <*> obj .: "envs"

data Lift1 f a = Lift1 { lower1 :: f a }

instance (FromJSON1 f, FromJSON a) => FromJSON (Lift1 f a) where
    parseJSON = fmap Lift1 . parseJSON1

-------------------------------------------------------------------------------
-- Opts
-------------------------------------------------------------------------------

data Opts = Opts
    { _optsCmd :: Cmd
    }
    deriving (Show)

-- makeLenses ''Opts

data Cmd
    = CmdEnv (Maybe EnvName) !UseSecrets
    | CmdRun (Maybe EnvName) !UseSecrets !UseStack !UseCabal ![String]
    | CmdInit
    | CmdListKeys
    | CmdAddKey Text Text
    | CmdDeleteKey Text
    | CmdGenPass
    deriving (Show)

data UseSecrets = UseSecrets | NoSecrets
    deriving (Show)

data UseStack = UseStack | NoStack
    deriving (Show)

data UseCabal = UseCabal | NoCabal
    deriving (Show)

-------------------------------------------------------------------------------
-- Parser
-------------------------------------------------------------------------------

optsParser :: O.Parser Opts
optsParser = fmap Opts $ O.subparser $ mconcat
    [ O.command "env"        $ O.info (O.helper <*> cmdEnvParser) $ O.progDesc "Print environment as shell script"
    , O.command "run"        $ O.info (O.helper <*> cmdRunParser) $ O.progDesc "Run command in the environment"
    , O.command "init"       $ O.info (O.helper <*> cmdInitParser) $ O.progDesc "Initialize the secrets file"
    , O.command "list-keys"  $ O.info (O.helper <*> cmdListKeysParser) $ O.progDesc "List all keys in the secret file"
    , O.command "add-key"    $ O.info (O.helper <*> cmdAddKeyParser) $ O.progDesc "Add secret key"
    , O.command "delete-key" $ O.info (O.helper <*> cmdDeleteKeyParser) $ O.progDesc "Delete secret key"
    , O.command "gen-pass"   $ O.info (O.helper <*> cmdGenPassParser) $ O.progDesc "Generate password using system entropy"
    ]

cmdEnvParser :: O.Parser Cmd
cmdEnvParser = CmdEnv
    <$> optional (textArgument $ O.metavar ":env" <> O.help "Environment name")
    <*> (O.flag UseSecrets NoSecrets $ O.short 'n' <> O.long "no-secrets" <> O.help "No secrets")

cmdRunParser :: O.Parser Cmd
cmdRunParser = CmdRun
    <$> optional (textOption $ O.short 'e' <> O.long "env" <> O.metavar ":env" <> O.help "Environment name")
    <*> (O.flag UseSecrets NoSecrets $ O.short 'n' <> O.long "no-secrets" <> O.help "No secrets")
    <*> (O.flag NoStack UseStack $ O.short 's' <> O.long "stack" <> O.help "Use stack exec")
    <*> (O.flag NoCabal UseCabal $ O.short 'c' <> O.long "cabal" <> O.help "Run first executable from cabal file")
    <*> many (O.strArgument $ O.metavar ":command" <> O.help "Command to run")

cmdInitParser :: O.Parser Cmd
cmdInitParser = pure CmdInit

cmdListKeysParser :: O.Parser Cmd
cmdListKeysParser = pure CmdListKeys

cmdAddKeyParser :: O.Parser Cmd
cmdAddKeyParser = CmdAddKey
    <$> textArgument (O.metavar ":key" <> O.help "secret key")
    <*> textArgument (O.metavar ":value" <> O.help "secret value")

cmdDeleteKeyParser :: O.Parser Cmd
cmdDeleteKeyParser = CmdDeleteKey
    <$> textArgument (O.metavar ":key" <> O.help "secret key")

cmdGenPassParser :: O.Parser Cmd
cmdGenPassParser = pure CmdGenPass

textArgument :: O.Mod O.ArgumentFields String -> O.Parser Text
textArgument mods = T.pack <$> O.strArgument mods

textOption :: O.Mod O.OptionFields String -> O.Parser Text
textOption mods = T.pack <$> O.strOption mods

-------------------------------------------------------------------------------
-- Execution
-------------------------------------------------------------------------------

execCmd :: Opts -> IO ()
execCmd (Opts cmd) = f $ case cmd of
    CmdEnv envName useSecrets ->
        execCmdEnv envName useSecrets
    CmdRun envName useSecrets useStack useCabal params ->
        execCmdRun envName useSecrets useStack useCabal params
    CmdInit        -> execCmdInit
    CmdListKeys    -> execCmdListKeys
    CmdAddKey k v  -> execCmdAddKey k v
    CmdDeleteKey k -> execCmdDeleteKey k
    CmdGenPass     -> execCmdGenPass
  where
    f :: Tajna () -> IO ()
    f m = do
      x <- runExceptT m
      case x of
          Right _  -> pure ()
          Left (InvalidYaml fp err) -> putStrLn $ "ERROR: Invalid yaml " <> fp <> " -- " <> err
          Left (UnknownSecret s)    -> putStrLn $ "ERROR: Unknown secret " <> T.unpack s
          Left NoCabalFile          -> putStrLn $ "ERROR: No *.cabal file in the directory"
          Left (NoExeInCabal fp)    -> putStrLn $ "ERROR: No executables in cabal file " <> fp


execCmdEnv :: Maybe EnvName -> UseSecrets -> Tajna ()
execCmdEnv envName' useSecrets = do
    (env, _) <- getTajnaEnv useSecrets envName'
    void $ for_ (sort $ HM.toList env) $ \(k, v) ->
        liftIO $ T.putStrLn $ "export " <> k <> "=\"" <> v <> "\""

execCmdRun :: Maybe EnvName -> UseSecrets -> UseStack -> UseCabal -> [String] -> Tajna ()
execCmdRun envName' useSecrets useStack useCabal params = do
    (env, rtsopts) <- getTajnaEnv useSecrets envName'
    origEnv <- getEnvironment'
    let env' = bimap T.unpack T.unpack <$> HM.toList (env <> origEnv)

    -- Detect executable name
    (cmd', args') <- case useCabal of
        UseCabal -> (,) <$> getCabalExecutable <*> pure params
        NoCabal  -> case params of
            []    -> error $ "No command specified"
            (a:b) -> pure (a, b)

    let args'' = case T.words rtsopts of
            [] -> args'
            ws -> "+RTS" : map T.unpack ws ++ "-RTS" : args'

    -- If use stack: prepend `stack exec`
    let (cmd, args) = case useStack of
            UseStack -> ("stack", "exec" : "--" : cmd' : args'')
            NoStack  -> (cmd', args'')

    -- Run command
    liftIO $ callProcessInEnv cmd args env'

execCmdInit :: Tajna ()
execCmdInit = writeTajnaSecrets mempty

execCmdListKeys :: Tajna ()
execCmdListKeys = do
    secrets <- readTajnaSecrets
    for_ (sort $ HM.toList secrets) $ \(k, v) ->
        liftIO $ T.putStrLn $ T.justifyLeft 30 ' ' k <> " : " <> v

execCmdAddKey :: Text -> Text -> Tajna ()
execCmdAddKey key value = do
    secrets <- readTajnaSecrets
    -- we don't overwrite!
    let secrets' = secrets & at key %~ \old -> old <|> Just value
    writeTajnaSecrets secrets'

execCmdDeleteKey :: Text -> Tajna ()
execCmdDeleteKey key = do
    secrets <- readTajnaSecrets
    let secrets' = secrets & at key .~ Nothing
    writeTajnaSecrets secrets'

execCmdGenPass :: Tajna ()
execCmdGenPass = liftIO $ generatePassword 32
  where
    chars :: String
    chars = ['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9'] ++ "!@#?-_,."

    generatePassword :: Int -> IO ()
    generatePassword l = do
        g <- newGenIO :: IO HmacDRBG
        p <- either throwM pure $ evalCRand (generatePassword' l) $ g
        putStrLn p

    generatePassword' :: Int -> CRand HmacDRBG GenError String
    generatePassword' l = sequence $ replicate l (element chars)

    element :: MonadCRandomR e m => [a] -> m a
    element list = (list !!) <$> getCRandomR (0, length list - 1)

writeTajnaSecrets :: HashMap Text Text -> Tajna ()
writeTajnaSecrets secrets = liftIO $ do
    home      <- getEnv "HOME"
    identity  <- T.strip <$> T.readFile (home <> "/.tajna/identity")
    (ec, encrypted, err) <- ProcessBS.readProcessWithExitCode
        "gpg2" [ "-e", "-r", identity ^. unpacked ] (encode secrets)
    BS.hPutStr stderr err
    forOf_ _ExitFailure ec $ \_ -> exitFailure
    BS.writeFile (home <> "/.tajna/secrets.yaml.encrypted") encrypted

readTajnaSecrets :: Tajna (HashMap Text Text)
readTajnaSecrets = do
    home <- liftIO $ getEnv "HOME"
    identity <- liftIO $ T.readFile $ home <> "/.tajna/identity"
    decodeFileEitherTajna (Just identity) $ home <> "/.tajna/secrets.yaml.encrypted"

-- | Get's environment and rts options
getTajnaEnv :: UseSecrets -> Maybe EnvName -> Tajna (HashMap Text Text, Text)
getTajnaEnv useSecrets envName' = do
    config <- decodeFileEitherTajna Nothing "tajna.yaml" :: Tajna (Config Identity)
    local <- decodeFileEitherTajna Nothing "tajna.local.yaml" `catch` defaultLocal
    let envName = fromMaybe (config ^. configDefEnv . _Wrapped) envName'
    env <- case config ^. configEnvs . at envName of
        Nothing  -> error $ "Non-existing environment: " <> T.unpack envName
        Just env -> flattenEnv (HM.union (fromMaybe mempty $ local ^. configEnvs . at envName) env)
    pure (env, config ^. configRtsOpts)
  where
    defaultLocal :: IOError -> Tajna (Config Proxy)
    defaultLocal _ = pure $ Config Proxy mempty mempty

    flattenEnv :: HashMap k EnvValue -> Tajna (HashMap k Text)
    flattenEnv env = do
        environment <- getEnvironment'
        case traverse (f environment) env of
            Just env' -> pure env'
            Nothing   -> case useSecrets of
                UseSecrets -> flattenEnvSecrets env
                NoSecrets  -> pure $ HM.mapMaybe (f environment) env
      where
        f :: HashMap Text Text -> EnvValue -> Maybe Text
        f e (EVPublic t) = Just $ expandEnvVar e t
        f _ (EVSecret _) = Nothing

    flattenEnvSecrets :: HashMap k EnvValue -> Tajna (HashMap k Text)
    flattenEnvSecrets env = do
        environment <- getEnvironment'
        secrets <- readTajnaSecrets
        traverse (f secrets environment) env
      where
        f :: HashMap Text Text -> HashMap Text Text -> EnvValue -> Tajna Text
        f _ e (EVPublic t) = pure $ expandEnvVar e t
        f s _ (EVSecret k) =
            maybe (throwE $ UnknownSecret k) pure $
                HM.lookup k s

main :: IO ()
main =
    O.execParser opts >>= execCmd
  where
    opts = O.info (O.helper <*> optsParser) $ mconcat
        [ O.fullDesc
        , O.progDesc "Helper for 12factor apps"
        , O.header "tajna"
        ]

-------------------------------------------------------------------------------
-- Process extras
-------------------------------------------------------------------------------

callProcessInEnv :: FilePath -> [String] -> [(String, String)] -> IO ()
callProcessInEnv cmd args env = do
    (_, _, _, p) <- createProcess $ (proc cmd args)
        { Process.delegate_ctlc = True
        , Process.env           = Just env
        }
    exit_code <- waitForProcess p
    case exit_code of
      ExitSuccess   -> return ()
      ExitFailure r -> error $ show r

-------------------------------------------------------------------------------
-- System.Environment extras
-------------------------------------------------------------------------------

getEnvironment' :: MonadIO m => m (HashMap Text Text)
getEnvironment' =
    HM.fromList . fmap (bimap T.pack T.pack) <$> liftIO getEnvironment

expandEnvVar :: HashMap Text Text -> Text -> Text
expandEnvVar hm = replace re
  where
    re :: RE' Text
    re = f <$ sym '$' <*> some (psym isAlpha)

    f :: String -> Text
    f varname = fromMaybe "" $ HM.lookup (T.pack varname) hm

-------------------------------------------------------------------------------
-- Data.Yaml extras
-------------------------------------------------------------------------------

decodeFileEitherTajna :: FromJSON a => Maybe Text -> FilePath -> Tajna a
decodeFileEitherTajna midentity fp = do
    contents <- liftIO $ case midentity of
        Nothing -> BS.readFile fp
        Just _identity -> do
            encrypted <- BS.readFile fp
            (ec, encoded, err) <- ProcessBS.readProcessWithExitCode
                "gpg2" ["-d"] encrypted
            BS.hPutStr stderr err
            forOf_ _ExitFailure ec $ \_ -> exitFailure
            pure encoded

    either (throwE . InvalidYaml fp . show) pure (decodeEither' contents)

-------------------------------------------------------------------------------
-- Cabal stuff
-------------------------------------------------------------------------------

findCabalFile :: Tajna FilePath
findCabalFile = do
    files <- liftIO $ getDirectoryContents "."
    case filter (isSuffixOf ".cabal") files of
        [cabalfile] -> pure cabalfile
        _           -> throwE $ NoCabalFile

cabalFileFirstExecutable :: MonadIO m => FilePath -> m (Maybe String)
cabalFileFirstExecutable cabalFile = do
#if MIN_VERSION_Cabal(2,0,0)
    gpd <- liftIO $ readGenericPackageDescription normal cabalFile
#else
    gpd <- liftIO $ readPackageDescription normal cabalFile
#endif
    case condExecutables gpd of
        ((name, _) : _) ->
#if MIN_VERSION_Cabal(2,0,0)
            pure $ Just $ unUnqualComponentName name
#else
            pure $ Just name
#endif
        []              -> pure Nothing


getCabalExecutable :: Tajna FilePath
getCabalExecutable = do
    cabalFile <- findCabalFile
    exe <- cabalFileFirstExecutable cabalFile
    maybe (throwE $ NoExeInCabal cabalFile) pure exe
