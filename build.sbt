ThisBuild / scalaVersion := "3.3.3"

lazy val root = (project in file("."))
  .settings(
    name := "scaledger-ecdsa",

    libraryDependencies ++= Seq(
      "org.typelevel" %% "cats-effect" % "3.5.4"
    )
  )
