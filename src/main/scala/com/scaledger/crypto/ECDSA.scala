package com.scaledger.crypto

import cats.effect.IO
import cats.effect.kernel.Sync
import cats.syntax.apply.*

import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom}
import scala.annotation.{tailrec, targetName}

object ECDSA {
  private val charset = StandardCharsets.UTF_8
  private val coefficientA = BigInt(0)
  private val coefficientB = BigInt(7)
  private val groupOrder: BigInt = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
  private val secp256k1Prime = BigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
  private val generatorPoint = CurvePoint(
    BigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
    BigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
  )

  sealed trait CurvePoint {
    def x: BigInt

    def y: BigInt

    @targetName("add")
    infix def +(pointB: CurvePoint): CurvePoint =
      if (this == PointAtInfinity) pointB
      else if (pointB == PointAtInfinity) this
      else {
        val s = slope(this, pointB)
        val xr = (s.pow(2) - this.x - pointB.x) % secp256k1Prime
        CurvePoint(xr, (s * (this.x - xr) - this.y) % secp256k1Prime)
      }

    def double: CurvePoint = this + this

    private def slope(pointA: CurvePoint, pointB: CurvePoint): BigInt =
      if (pointA == pointB) (3 * pointA.x.pow(2) + coefficientA) * (2 * pointA.y).modInverse(secp256k1Prime)
      else (pointB.y - pointA.y) * (pointB.x - pointA.x).modInverse(secp256k1Prime)
  }

  object CurvePoint {
    def apply(x: BigInt, y: BigInt): CurvePoint = CurvePointCons(x, y)
  }

  case object PointAtInfinity extends CurvePoint {
    override val x: BigInt = 0
    override val y: BigInt = 0
  }

  case class CurvePointCons(override val x: BigInt, override val y: BigInt) extends CurvePoint

  case class Signature(r: BigInt, s: BigInt) {
    def verify(message: String, publicKey: PublicKey): IO[Boolean] = for {
      hashedMessage <- message.sha256BigInt
      w = s.modInverse(groupOrder)
      point = scalarMult((hashedMessage * w).mod(groupOrder)) + scalarMult((r * w).mod(groupOrder), publicKey.point)
    } yield point != PointAtInfinity && r == point.x.mod(groupOrder)

    override def toString: String = s"$r|$s"
  }

  object Signature {
    def apply(str: String): Signature = {
      val Array(r, s) = str.split('|').map(BigInt(_))
      Signature(r, s)
    }
  }

  sealed trait Key {
    def serialize: String

    def hash: IO[String] =
      toString.sha256

    override def toString: String = serialize
  }

  case class PrivateKey(value: BigInt) extends Key {
    def sign(message: String): IO[Signature] =
      (generateNonZero, message.sha256BigInt).mapN { (k, hashedMessage) =>
        val r = scalarMult(k).x.mod(groupOrder)
        Signature(r, (k.modInverse(groupOrder) * (hashedMessage + r * value)).mod(groupOrder))
      }

    override def serialize: String = value.toString
  }

  object PrivateKey {
    def apply(value: String): PrivateKey = PrivateKey(BigInt(value))
  }

  case class PublicKey(point: CurvePoint) extends Key {
    override def serialize: String = s"${point.x}|${point.y}"
  }

  object PublicKey {
    def apply(str: String): PublicKey = {
      PublicKey(str.splitToBigInts)
    }

    def apply(array: Array[BigInt]): PublicKey = {
      require(array.length == 2, "PublicKey requires an array of exactly two elements.")
      PublicKey(CurvePoint(array.head, array(1)))
    }
  }

  case class KeyPair(privateKey: PrivateKey, publicKey: PublicKey) {
    override def toString: String = s"$privateKey|$publicKey"
  }

  object KeyPair {
    def apply(str: String): KeyPair = {
      KeyPair(str.splitToBigInts)
    }

    def apply(array: Array[BigInt]): KeyPair = {
      require(array.length == 3, "KeyPair requires an array of exactly three elements.")
      KeyPair(PrivateKey(array.head), PublicKey(array.tail))
    }

    def generate: IO[KeyPair] = for {
      key <- generateNonZero
    } yield KeyPair(PrivateKey(key), PublicKey(scalarMult(key)))

  }

  def scalarMult(k: BigInt, point: CurvePoint = generatorPoint): CurvePoint = {
    @tailrec
    def scale(scalarStep: BigInt, result: CurvePoint, current: CurvePoint): CurvePoint =
      if (scalarStep == 0) result
      else scale(scalarStep >> 1, if ((scalarStep & 1) == 1) result + current else result, current.double)

    if k == 0 then PointAtInfinity else scale(k, PointAtInfinity, point)
  }

  private def generateNonZero: IO[BigInt] =
    Sync[IO].delay(new SecureRandom()).map { random =>

    @tailrec
    def generate: BigInt = {
      val key = BigInt(groupOrder.bitLength, random).mod(groupOrder)
      if key != 0 then key else generate
    }

    generate
  }

  extension (text: String) {
    def splitToBigInts: Array[BigInt] =
      text.split('|').map(BigInt(_))

    def sha256Hash: IO[Array[Byte]] =
      Sync[IO].delay(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)))

    def sha256BigInt: IO[BigInt] =
      sha256Hash.map(BigInt(1, _))

    def sha256: IO[String] =
      sha256Hash.map(_.map("%02x".format(_)).mkString)
  }
}
