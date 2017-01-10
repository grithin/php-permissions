<?
/* About
Flat RBAC, not indended for use on id-ed resources (use ACL instead)

Permission check follows:
-	user has permission?
-	user is excluded from permission?
-	user has role with permission?

*/

namespace Grithin\User;

use \Grithin\Time;
use \Grithin\Debug;

/*
Permissions

CREATE TABLE `user` (
	`id` bigint not null auto_increment,
	`display_name` varchar(100),
	primary key (`id`)
) engine=InnoDB charset=utf8;

--

CREATE TABLE `rbac_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(250) NOT NULL,
  `details__json` text,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 ;

CREATE TABLE `rbac_roles_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `role_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `role_id` (`role_id`,`permission_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 ;

CREATE TABLE `rbac_users_role` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `role_id` int(11) NOT NULL,
  `user_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`,`role_id`),
  KEY `role_id` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ;

CREATE TABLE `rbac_users_permission` (
  `id` bigint(11) NOT NULL AUTO_INCREMENT,
  `user_id` bigint(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  `has` BOOL DEFAULT 1 NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`,`permission_id`),
  KEY `permission_id` (`permission_id`,`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ;

CREATE TABLE `rbac_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(250) NOT NULL,
  `details__json` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 ;


insert into user (display_name) values ('test1'), ('test2');
insert into rbac_role (name) values ('admin'), ('moderator'), ('basic');
insert into rbac_permission (name) values ('can_delete_post'), ('can_update_post'),  ('can_view_post');


*/

class Rbac{
	use \Grithin\VariedParameter;
	use \Grithin\Memoized;
	use \Grithin\LocalCopy;

	/* params
	options = {'db':< db instance >}
	*/
	public function __construct($options=[]){
		$this->db = $options['db'] ? $options['db'] : \Grithin\Db::primary();

		$this->options = $options;
	}


	public function a_users_roles_ids($user_id){
		return $this->db->column('rbac_users_role',['user_id'=>$user_id],'role_id');
	}
	public function a_users_roles($user_id){
		return $this->db->rows('rbac_users_role',['user_id'=>$user_id]);
	}


	public function role($role){
		return $this->item_by_thing('role', $role);
	}
	public function role_id_by_name($name){
		return $this->role_by_name($name)['id'];
	}
	public function role_by_name($name){
		return $this->local_get_or_set('role', $name, [$this, 'role_by_name__fresh'] );
	}
	public function role_by_name__fresh($name){
		return $this->db->as_row('select * from rbac_role where name = ?',[$name]);
	}
	public function role_by_id($id){
		return $this->local_get_or_set('role', $id, [$this, 'role_by_id__fresh'] );
	}
	public function role_by_id__fresh($id){
		return $this->db->as_row('select * from rbac_role where id = ?',[$id]);
	}


	public function has_role($user_id, $role){
		$role_id = $this->role($role)['id'];
		return $this->has_role_by_id($user_id, $role_id);
	}
	public function has_role_by_id($user_id, $role_id){
		return (bool) $this->conditional_memoized('users_role_by_id', [$user_id, $role_id]);
	}
	public function users_role_by_id($user_id, $role_id){
		return $this->db->as_row('select * from rbac_users_role where role_id = ? and user_id = ?', [$role_id, $user_id]);
	}


	public function permission($thing){
		return $this->item_by_thing('permission', $thing);
	}
	public function permission_id_by_name($name){
		return $this->permission_by_name($name)['id'];
	}
	public function permission_by_name($name){
		return $this->local_get_or_set('permission', $name, [$this, 'permission_by_name__fresh'] );
	}
	public function permission_by_name__fresh($name){
		return $this->db->as_row('select * from rbac_permission where name = ?',[$name]);
	}
	public function permission_by_id($id){
		return $this->local_get_or_set('permission', $id, [$this, 'permission_by_id__fresh'] );
	}
	public function permission_by_id__fresh($id){
		return $this->db->as_row('select * from rbac_permission where id = ?',[$id]);
	}


	public function role_has_permission($role, $permission){
		$role_id = $this->id_by_thing('role', $role);
		$permission_id = $this->id_by_thing('rbac_permission', $permission);
		return (bool) $this->conditional_memoized('role_has_permission_by_ids', [$role_id, $permission_id]);
	}
	public function role_has_permission_by_ids($role_id, $permission_id){
		return (bool) $this->db->as_value('select 1 from rbac_roles_permission where role_id = ? and permission_id = ?', [$role_id, $permission_id]);
	}


	public function has_permission($user_id, $permission){
		return $this->user_has_permission($user_id, $permission);
	}
	public function user_has_permission($user_id, $permission){
		$permission_id = $this->id_by_thing('permission', $permission);
		$has = $this->user_has_direct_permission($user_id, $permission_id);
		if(\Grithin\Tool::isInt($has)){
			return $has;
		}

		$role_ids = $this->conditional_memoized('a_users_roles_ids', [$user_id]);
		foreach($role_ids as $role_id){
			$has = $this->role_has_permission($role_id, $permission_id);
			if($has){
				return $has;
			}
		}
		return false;
	}
	/*
	return
		0: excluded
		1: has
		false: not found
	*/
	public function user_has_direct_permission($user_id, $permission){
		$permission_id = $this->id_by_thing('permission', $permission);
		return $this->db->as_value('select '.$this->db->quoteIdentity('has').' from rbac_users_permission where user_id = ? and permission_id = ?', [$user_id, $permission_id]);
	}



	#+	management functions {
	public function users_role_insert($user_id, $role){
		$role_id = $this->id_by_thing('role', $role);
		return $this->db->id('rbac_users_role', ['user_id'=>$user_id, 'role_id'=>$role_id]);
	}
	public function users_role_delete($user_id, $role){
		$role_id = $this->id_by_thing('role', $role);
		return $this->db->delete('rbac_users_role', ['user_id'=>$user_id, 'role_id'=>$role_id]);
	}
	public function role_insert($role){
		return $this->db->insert('rbac_role', $role);
	}
	public function role_delete($role){
		$role_id = $this->id_by_thing('role', $role);
		$this->db->delete('rbac_role', ['id'=>$role_id]);
		$this->db->delete('rbac_roles_permission', ['role_id'=>$role_id]);
		$this->db->delete('rbac_users_role', ['role_id'=>$role_id]);
	}
	public function roles_permission_give($role, $permission){
		$this->roles_permission_insert($role, $permission);
	}
	public function roles_permission_insert($role, $permission){
		$role_id = $this->id_by_thing('role', $role);
		$permission_id = $this->id_by_thing('permission', $permission);
		return $this->db->replace('rbac_roles_permission', ['role_id'=>$role_id, 'permission_id'=>$permission_id]);
	}
	public function roles_permission_delete($role, $permission){
		$role_id = $this->id_by_thing('role', $role);
		$permission_id = $this->id_by_thing('permission', $permission);
		return $this->db->delete('rbac_users_permission', ['role_id'=>$role_id, 'permission_id'=>$permission_id]);
	}

	public function users_permission_give($user_id, $permission){
		$permission_id = $this->id_by_thing('permission', $permission);
		return $this->db->replace('rbac_users_permission', ['user_id'=>$user_id, 'permission_id'=>$permission_id, 'has'=>1]);
	}
	public function users_permission_exclude($user_id, $permission){
		$permission_id = $this->id_by_thing('permission', $permission);
		return $this->db->replace('rbac_users_permission', ['user_id'=>$user_id, 'permission_id'=>$permission_id, 'has'=>0]);
	}
	public function users_permission_delete($user_id, $permission){
		$permission_id = $this->id_by_thing('permission', $permission);
		return $this->db->delete('rbac_users_permission', ['user_id'=>$user_id, 'permission_id'=>$permission_id]);
	}

	public function all_assigned_permissions_clear(){
		$this->db->exec('truncate rbac_users_permission');
		$this->db->exec('truncate rbac_roles_permission');
	}
	#+	}

}

/* testing
$assert = function($ought, $is){
	if($ought != $is){
		throw new Exception('ought is not is : '.\Grithin\Debug::pretty([$ought, $is]));
	}
};
$rbac = new Grithin\User\Rbac();

$rbac->all_assigned_permissions_clear();
$rbac->users_role_insert(1, 'admin');
$assert(true, $rbac->has_role(1, 'admin'));
$assert(false, $rbac->has_role(2, 'admin'));
$assert(false, $rbac->has_permission(2, 'can_delete_post'));
$rbac->users_permission_give(2, 'can_delete_post');
$assert(true, $rbac->has_permission(2, 'can_delete_post'));
$rbac->roles_permission_give('admin', 'can_delete_post');
$assert(true, $rbac->has_permission(1, 'can_delete_post'));
$rbac->users_permission_exclude(1, 'can_delete_post');
$assert(false, $rbac->has_permission(1, 'can_delete_post'));
*/