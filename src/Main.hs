{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
module Main (main) where

import Prelude        ()
import Prelude.Compat

import Control.Applicative        (many, optional, some)
import Control.Lens               (makeLenses, (^.))
import Control.Monad              (void)
import Control.Monad.IO.Class     (MonadIO (..))
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Data.Aeson                 (FromJSON (..), Value (..), withObject, (.:))
import Data.Aeson.Types           (typeMismatch)
import Data.Bifunctor             (bimap)
import Data.Char                  (isAlpha)
import Data.HashMap.Strict        (HashMap)
import Data.List                  (isSuffixOf)
import Data.Maybe                 (fromMaybe)
import Data.Monoid                ((<>))
import Data.Text                  (Text)
import Data.Yaml                  (decodeFileEither)
import System.Directory           (getDirectoryContents)
import System.Environment         (getEnv, getEnvironment)
import System.Exit                (ExitCode (..))
import System.Process             (createProcess, proc, waitForProcess)

import Text.Regex.Applicative.Text (RE', psym, replace, sym)

import Distribution.PackageDescription       (GenericPackageDescription (..))
import Distribution.PackageDescription.Parse (readPackageDescription)
import Distribution.Verbosity                (normal)

import qualified Data.HashMap.Strict as HM
import qualified Data.Text           as T
import qualified Data.Text.IO        as T
import qualified Options.Applicative as O
import qualified System.Process      as Process

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

data Config = Config
    { _configDefEnv :: !EnvName
    , _configEnvs   :: !(HashMap EnvName Env)
    }
    deriving (Show)

makeLenses ''Config

instance FromJSON Config where
    parseJSON = withObject "Confog" $ \obj -> Config
        <$> obj .: "default"
        <*> obj .: "envs"

-------------------------------------------------------------------------------
-- Opts
-------------------------------------------------------------------------------

data Opts = Opts
    { _optsCmd :: Cmd
    }
    deriving (Show)

-- makeLenses ''Opts

data Cmd
    = CmdEnv (Maybe EnvName)
    | CmdRun (Maybe EnvName) !UseStack !UseCabal ![String]
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
    [ O.command "env" $ O.info (O.helper <*> cmdEnvParser) $ O.progDesc "Print environment as shell script"
    , O.command "run" $ O.info (O.helper <*> cmdRunParser) $ O.progDesc "Run command in the environment"
    ]

cmdEnvParser :: O.Parser Cmd
cmdEnvParser = CmdEnv
    <$> optional (textArgument $ O.metavar ":env" <> O.help "Environment name")

cmdRunParser :: O.Parser Cmd
cmdRunParser = CmdRun
    <$> optional (textOption $ O.short 'e' <> O.long "env" <> O.metavar ":env" <> O.help "Environment name")
    <*> (O.flag NoStack UseStack $ O.short 's' <> O.long "stack" <> O.help "Use stack exec")
    <*> (O.flag NoCabal UseCabal $ O.short 'c' <> O.long "cabal" <> O.help "Run first executable from cabal file")
    <*> many (O.strArgument $ O.metavar ":command" <> O.help "Command to run")

textArgument :: O.Mod O.ArgumentFields String -> O.Parser Text
textArgument mods = T.pack <$> O.strArgument mods

textOption :: O.Mod O.OptionFields String -> O.Parser Text
textOption mods = T.pack <$> O.strOption mods

-------------------------------------------------------------------------------
-- Execution
-------------------------------------------------------------------------------

execCmd :: Opts -> IO ()
execCmd (Opts cmd) = f $ case cmd of
    CmdEnv envName ->
        execCmdEnv envName
    CmdRun envName useStack useCabal params ->
        execCmdRun envName useStack useCabal params
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


execCmdEnv :: Maybe EnvName -> Tajna ()
execCmdEnv envName' = do
    env <- getTajnaEnv envName'
    void $ flip HM.traverseWithKey env $ \k v ->
        liftIO $ T.putStrLn $ "export " <> k <> "=\"" <> v <> "\""

execCmdRun :: Maybe EnvName -> UseStack -> UseCabal -> [String] -> Tajna ()
execCmdRun envName' useStack useCabal params = do
    env <- getTajnaEnv envName'
    origEnv <- getEnvironment'
    let env' = bimap T.unpack T.unpack <$> HM.toList (env <> origEnv)

    -- Detect executable name
    (cmd', args') <- case useCabal of
            UseCabal -> (,) <$> getCabalExecutable <*> pure params
            NoCabal  -> case params of
                []    -> error $ "No command specified"
                (a:b) -> pure (a, b)

    -- If use stack: prepend `stack exec`
    let (cmd, args) = case useStack of
            UseStack -> ("stack", "exec" : "--" : cmd' : args')
            NoStack  -> (cmd', args')

    -- Run command
    liftIO $ callProcessInEnv cmd args env'

getTajnaEnv :: Maybe EnvName -> Tajna (HashMap Text Text)
getTajnaEnv envName' = do
    config <- decodeFileEitherTajna "tajna.yaml"
    let envName = fromMaybe (config ^. configDefEnv) envName'
    case HM.lookup envName (config ^. configEnvs) of
        Nothing  -> error $ "Non-existing environment: " <> T.unpack envName
        Just env -> flattenEnv env
  where
    flattenEnv :: HashMap k EnvValue -> Tajna (HashMap k Text)
    flattenEnv env = do
        environtment <- getEnvironment'
        case traverse (f environtment) env of
            Just env' -> pure env'
            Nothing -> flattenEnvSecrets env
      where
        f :: HashMap Text Text -> EnvValue -> Maybe Text
        f e (EVPublic t) = Just $ expandEnvVar e t
        f _ (EVSecret _) = Nothing

    flattenEnvSecrets :: HashMap k EnvValue -> Tajna (HashMap k Text)
    flattenEnvSecrets env = do
        home <- liftIO $ getEnv "HOME"
        environtment <- getEnvironment'
        secrets <- decodeFileEitherTajna $ home <> "/.tajna/secrets.yaml"
        traverse (f secrets environtment) env
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

decodeFileEitherTajna :: FromJSON a => FilePath -> Tajna a
decodeFileEitherTajna fp = do
    e <- liftIO $ decodeFileEither fp
    either (throwE . InvalidYaml fp . show) pure e

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
    gpd <- liftIO $ readPackageDescription normal cabalFile
    case condExecutables gpd of
        ((name, _) : _) -> pure $ Just name
        []              -> pure Nothing


getCabalExecutable :: Tajna FilePath
getCabalExecutable = do
    cabalFile <- findCabalFile
    exe <- cabalFileFirstExecutable cabalFile
    maybe (throwE $ NoExeInCabal cabalFile) pure exe
