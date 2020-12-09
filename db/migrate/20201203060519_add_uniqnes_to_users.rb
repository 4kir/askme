class AddUniqnesToUsers < ActiveRecord::Migration[6.0]
  def change
    add_index :users, :email, unique: true
    add_index :users, :username, unique: true

    change_column_null :users, :username, false
  end
end
