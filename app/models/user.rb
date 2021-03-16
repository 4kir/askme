require 'openssl'

class User < ApplicationRecord
  ITERATIONS = 20000
  DIGEST = OpenSSL::Digest::SHA256.new
  USERNAME_REGEXP = /\A\w+\z/
  PROFILE_COLOR_REGEXP = /\A#([a-f\d]{3}){1,2}\z/

  attr_accessor :password

  has_many :questions, dependent: :delete_all

  validates :email, :username, presence: true
  validates :password, presence: true, on: :create
  validates :password, confirmation: true
  validates :email, :username, uniqueness: true
  validates :username, length: { maximum: 40 }
  validates :username, format: { with: USERNAME_REGEXP }
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :profile_color, format: { with: PROFILE_COLOR_REGEXP }
  validates :avatar_url, format: { with: URI.regexp }, allow_blank: true

  before_validation :username_and_email_downcase
  before_save :encrypt_password

  def self.authenticate(email, password)
    user = find_by(email: email&.downcase!)

    if user.present? && user.password_hash == User.hash_to_string(OpenSSL::PKCS5.pbkdf2_hmac(password, user.password_salt, ITERATIONS, DIGEST.length, DIGEST))
      user
    else
      nil
    end
  end

  def self.hash_to_string(password_hash)
    password_hash.unpack('H*')[0]
  end

  private

  def encrypt_password
    if self.password.present?
      self.password_salt = User.hash_to_string(OpenSSL::Random.random_bytes(16))
      self.password_hash = User.hash_to_string(
        OpenSSL::PKCS5.pbkdf2_hmac(self.password, self.password_salt, ITERATIONS, DIGEST.length, DIGEST)
      )
    end
  end

  def username_and_email_downcase
    username&.downcase!
    email&.downcase!
  end
end
