<?php
/**
* MySessions, by MyBBSecurity.net
* Author: Paul H.
* File: PATH_TO_MYBB/inc/plugins/mysessions.php
* Last modified: March 4, 2012
* Get support and ask questions at http://www.mybbsecurity.net
*/


// Disallow direct access to this file for security reasons
if(!defined("IN_MYBB"))
{
	die("Nope.  Also, the game.");
}


//okay boys, let's get this party started.

//add our hooks
//kill sessions
$plugins->add_hook("global_end", "mysessions_clean");
//Main MySessions function
$plugins->add_hook("usercp_start", "mysessions");
//detect multiple sessions
$plugins->add_hook("pre_output_page", "mysessions_multiple_alert");

//basic plugin info for ACP
function mysessions_info()
{
	return array(
		"name"			=> "MySessions",
		"description"	=> "MySessions allows users to view all of their account's (or all accounts, based on settings) current sessions and log out any sessions they find suspicious.  It displays a dismissable alert when there are multiple sessions on the account.   Based on the functionality found in Gmail and Deviantart.",
		"website"		=> "https://github.com/PenguinPaul/mysessions",
		"author"		=> "MyBB Security Group", //formerly Paul H. until we decided all MyBB Security plugins should by MyBBSec branded
		"authorsite"	=> "http://www.mybbsecurity.net",
		"version"		=> "1.3.1",
		"guid" 			=> "",
		"compatibility" => "*"
	);
}

function mysessions_install()
{
	global $db;

	//settings group
	$group = array(
		'gid'			=> 'NULL',
		'name'			=> 'mysessions',
		'title'			=> 'MySessions Settings',
		'description'	=> 'Settings for the MySessions plugin.',
		'disporder'		=> '0',
		'isdefault'		=> 'no',
	);
	$db->insert_query('settinggroups', $group);
	$gid = $db->insert_id();
	
	//settings
	$setting = array(
		'name'			=> 'mysessions_supergroups',
		'title'			=> 'Super Groups',
		'description'	=> 'A CSV of groups that can see and manage all sessions.',
		'optionscode'	=> 'text',
		'value'			=> '4',
		'disporder'		=> 1,
		'gid'			=> intval($gid),
	);
	$db->insert_query('settings', $setting);	

	$setting = array(
		'name'			=> 'mysessions_normgroups',
		'title'			=> 'Normal Groups',
		'description'	=> 'A CSV of groups that can see and manage their own sessions.  Groups not in this list or the above cannot manage sessions at all.',
		'optionscode'	=> 'text',
		'value'			=> '2,3,6',
		'disporder'		=> 2,
		'gid'			=> intval($gid),
	);
	$db->insert_query('settings', $setting);		
	
	rebuild_settings();

	//make our DB table
	$db->write_query("CREATE TABLE `".TABLE_PREFIX."mysessions_kill` (
  `kid` int(11) NOT NULL auto_increment,
  `uid` int(11) NOT NULL,
  `sid` text NOT NULL,
  `timestamp` bigint(30) NOT NULL,
  KEY `kid` (`kid`)
) ENGINE=MyISAM  ".$db->build_create_table_collation().";");	

}

function mysessions_is_installed()
{
	global $db;
	//it's installed if the DB table exists
	return $db->table_exists("mysessions_kill");
}

function mysessions_activate()
{
	global $db;
	require_once MYBB_ROOT."/inc/adminfunctions_templates.php";
	//get rid of the MySessions option if it's already there
	mysessions_deactivate();
	
	if(!$db->field_exists("uid","mysessions_kill"))
	{
		$db->add_column("mysessions_kill","uid","int(11) NOT NULL");
	}
	
	//add MySessions option to User CP menu
	find_replace_templatesets("usercp_nav_misc", "#".preg_quote('</tbody>')."#i", '<tr><td class="trow1 smalltext"><a href="usercp.php?action=mysessions"><img src="http://icons.iconarchive.com/icons/famfamfam/silk/16/key-go-icon.png" alt="key"/>&nbsp; MySessions</a></td></tr></tbody>');
}

function mysessions_deactivate()
{
	require_once MYBB_ROOT."/inc/adminfunctions_templates.php";
	//delete MySessions option to User CP menu
	find_replace_templatesets("usercp_nav_misc", "#".preg_quote('<tr><td class="trow1 smalltext"><a href="usercp.php?action=mysessions"><img src="http://icons.iconarchive.com/icons/famfamfam/silk/16/key-go-icon.png" alt="key"/>&nbsp; MySessions</a></td></tr>')."#i", '');
}

function mysessions_uninstall()
{
	global $db;
	
	$db->query("DELETE FROM ".TABLE_PREFIX."settings WHERE name IN ('mysessions_supergroups','mysessions_normgroups')");
	$db->query("DELETE FROM ".TABLE_PREFIX."settinggroups WHERE name='mysessions'");
	rebuild_settings(); 
	//I lost the game
	$db->write_query("DROP TABLE ".TABLE_PREFIX."mysessions_kill");			
}

/* This function kills the current session if it is flagged to be ended */
function mysessions_clean()
{
	global $mybb,$db,$plugins,$session,$lang,$theme,$headerinclude;

	//get rid of session kills we don't need - the session has already expired
	$t2d = time() - 1800; //1800 seconds is 15 minutes
	$dq = $db->query("DELETE FROM ".TABLE_PREFIX."mysessions_kill WHERE timestamp<'".$t2d."'");
	
	//get the session data on our current session
	$query = $db->simple_select("mysessions_kill","*", "sid='{$session->sid}'");

	//is our session flagged fo deletion?
	if($db->num_rows($query) != '0') {
		//yes it is, run MyBB logout procedure.
		
		//copied shamelessly from ./member.php
		$plugins->run_hooks("member_logout_start");
		
		my_unsetcookie("mybbuser");
		my_unsetcookie("sid");
		
		if($mybb->user['uid'])
		{
			$time = TIME_NOW;
			$lastvisit = array(
				"lastactive" => $time-900,
				"lastvisit" => $time,
			);
			$db->update_query("users", $lastvisit, "uid='".$mybb->user['uid']."'");
			$db->delete_query("sessions", "sid='".$session->sid."'");
			$db->delete_query("mysessions_kill", "sid='".$session->sid."'");
		}
		
		redirect("index.php", "You have been logged out", "Logout Notice");
		
		$plugins->run_hooks("member_logout_end");
		
	}
}

function mysessions()
{
	global $mybb,$db,$header,$footer,$headerinclude,$theme,$lang,$usercpnav,$usercpmenu,$session;
	
	//get the user permissions
	$msal = mysession_access_level();

	//are we searching for a certain user's sessions?
	if($mybb->input['do'] == 'search_mysessions')
	{
		//can the user even search for other user's sessions?
		if($msal != 2) {error_no_permission();}
		
		//escape username
		$username = $db->escape_string($mybb->input['username']);
		//get user
		$user = $db->fetch_array($db->simple_select("users","*", "username='{$username}'"));
		
		//is this a real user?
		if(!is_null($user))
		{	
			//yes it is, return results
			header("Location: usercp.php?action=mysessions&uid={$user['uid']}");	
		} else {
			//no it's not, return error
			header("Location: usercp.php?action=mysessions&error=invalid-username");	
		}		
	}	

	//are we flagging a session for logout or cancelling a kill request?
	if($mybb->input['do'] == 'manage_mysessions')
	{	
		//can this usergroup manage sessions?
		if($msal == 0)	{error_no_permission();}
		
		//no errors... yet
		$errors = '';
		
		//CSRF?
		if(!verify_post_check($mybb->input['hash'],true)) {$errors .= inline_error("An invalid verification code was given.  Please try again.","Invalid Verification Code");}
		
		//are we flagging a session?
		if(isset($mybb->input['delete']))
		{
			//are we doing a blank search?
			if($mybb->input['delete'] == '') {$errors .= inline_error("No SID selected.  Please try again.","No SID");}
			
			//ok, we have a valid SID var, clean it now to prevent SQLi
			$sid = $db->escape_string($mybb->input['delete']);
			
			//get the session info
			$query = $db->simple_select("sessions","*", "sid='{$sid}'");
			
			//is there a session with that SID?
			if($db->num_rows($query) == 0)
			{
				//nope, throw an error
				$errors .= inline_error("Invalid SID selected.  Please try again.","Invalid SID");
			} else {
				//sure it, flag for deletion
				
				//get session info
				$sinfo = $db->fetch_array($query);
				
				//if the SID isn't yours and you can only manage your own sessions...
				if($sinfo['uid'] != $mybb->user['uid'] && $msal == 1)
				{
					$errors .= inline_error("You cannot manage that session.","Invalid SID");
				}	
	
				//if we have no errors, go ahead and flag for deletion
				if($errors == '')
				{
					//kid is auto-increment
					$insert['kid'] = NULL;
					//user uid
					$insert['uid'] = $sinfo['uid'];
					//the session
					$insert['sid'] = $sid;
					//when we're flagging the session
					$insert['timestamp'] = time();
					
					//insert the request
					$db->insert_query("mysessions_kill",$insert);
					
					//and redirect, we're done here.
					redirect("usercp.php?action=mysessions","Session \"{$sid}\" will be logged out on the session's next action.", "Success");
				}
			}
		}
		
		//are we cancelling a request?
		if(isset($mybb->input['cancel']))
		{
			//are we doing a blank search?
			if($mybb->input['cancel'] == '') {$errors .= inline_error("No SID selected.  Please try again.","No SID");}
			
			//ok, we have a valid SID var, clean it now to prevent SQLi
			$sid = $db->escape_string($mybb->input['cancel']);
			
			//get the session info
			$query = $db->simple_select("mysessions_kill","*", "sid='{$sid}'");
			$sinfo = $db->fetch_array($query);
			
			//is there a session with that SID?
			if($db->num_rows($query) == 0)
			{
				//nope, throw an error
				$errors .= inline_error("Invalid SID selected.  Please try again.","Invalid SID");
			} else {
				//sure it, flag for deletion
				
				//if the SID isn't yours and you can only manage your own sessions...
				if($sinfo['uid'] != $mybb->user['uid'] && $msal == 1)
				{
					$errors .= inline_error("You cannot manage that session.","Invalid SID");
				}	
	
				//if we have no errors, go ahead and flag for deletion
				if($errors == '')
				{
					$db->delete_query("mysessions_kill","sid='{$sid}'");
					
					//and redirect, we're done here.
					redirect("usercp.php?action=mysessions","Logout request for session \"{$sid}\" was cancelled.", "Success");
				}
			}
		}	
	}
	
	
	//genereric MySessions UCP page
	if($mybb->input['action'] == 'mysessions')
	{
		//we'll need this later to display where users are in the table
		require_once(MYBB_ROOT."/inc/functions_online.php");
		
		//breadcrumb
		add_breadcrumb("MySessions");
	
		//see what this user can see
		if($msal == 0)	{/* nothing */ error_no_permission();}
		if($msal == 1)	{/* just their own sessions */ $extra = " WHERE uid='{$mybb->user['uid']}'";}
		if($msal == 2)
		{
			//everyone's sessions
			
			//but don't show guests, we can't log them out.
			$extra = " WHERE uid!='0'";
			
			//are we searching for a specific user?
			if(isset($mybb->input['uid']))
			{
				$extra .= " AND uid='".intval($mybb->input['uid'])."'";
				//extra stuff to add to the URL if we have multiple pages
				$eurl = "&amp;uid=".intval($mybb->input['uid']);
			}
		
			//are we looking for a specific IP address?
			if(isset($mybb->input['ip']))
			{
				$extra .= " AND ip='".$db->escape_string($mybb->input['ip'])."'";
				//extra stuff to add to the URL if we have multiple pages
				$eurl .= "&amp;ip=".htmlspecialchars_uni($mybb->input['ip']);
			}	
		
		}	
	
		//throw any errors we have.
		if($mybb->input['error'] == "invalid-username")
		{
			//user was searching usernames and didn't search a valid username
			$errors .= inline_error("The selected username is invalid.","Invalid Username");
		}	
	
	
		//pagination	
		if(!isset($mybb->input['page']))
		{
			$pagenum = 1;
		} else {
			$pagenum = intval($mybb->input['page']);
		}
		
		$limit .= " LIMIT ".(($pagenum-1)*10).", 10";	
								

		//are we viewing all current sessions, or ones pending deletion?
		if($mybb->input['view'] != 'pending')
		{	
			//we're looking at all current sessions, I guess.
			
			//table head
			$colspan = '6';
			$sessions = "<tr>
			<td class=\"tcat\" width=\"5\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>Username</strong></span></td>
			<td class=\"tcat\" width=\"85\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>SID</strong></span></td>
			<td class=\"tcat\" width=\"85\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>IP Address</strong></span></td>
			<td class=\"tcat\" width=\"85\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>User Agent</strong></span></td>
			<td class=\"tcat\" width=\"85\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>Location</strong></span></td>
			<td class=\"tcat\" width=\"24\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>Close Session</strong></span></td>
			</tr>";
			
			//get the sessions
			$query = $db->query("SELECT * FROM ".TABLE_PREFIX."sessions{$extra}{$limit}");
			$allq = $db->query("SELECT * FROM ".TABLE_PREFIX."sessions{$extra}");
			
			//display them
			while($row = $db->fetch_array($query))
			{
				//online location info
				$wolarr = fetch_wol_activity($row['location']);
				$wol = build_friendly_wol_location($wolarr);
				
				
				
				//sanitize to avoid XSS
				$row['useragent'] = htmlspecialchars_uni($row['useragent']);
				//$row['useranget'] is unclipped, $useragent will be if necessary
				$useragent = $row['useragent'];
				//clip if necessary
				if(strlen($useragent) > 10)
				{
					$useragent = substr($useragent,0,10)."...";
				}
				
				//get user info, specifically username
				$user = get_user($row['uid']);
				
				//build the user info, starting with profile link
				$userlink = build_profile_link($user['username'],$row['uid'],"_blank");
				//and ending with search for this user
				$userlink .= " <a href=\"usercp.php?action=mysessions&amp;uid={$row['uid']}\"><img src=\"http://icons.iconarchive.com/icons/deleket/scrap/16/Magnifying-Glass-icon.png\" alt=\"Search\" /></a>";
				
				/* copied from modcp.php */
				// Return GeoIP information if it is available to us
				if(function_exists('geoip_record_by_name'))
				{
					$ip_record = @geoip_record_by_name($mybb->input['ipaddress']);
					if($ip_record)
					{
						$ipaddress_location = "<br />".htmlspecialchars_uni($ip_record['country_name']);
						if($ip_record['city'])
						{
							$ipaddress_location .= $lang->comma.htmlspecialchars_uni($ip_record['city']);
						}
					}
				}
				
				$ipaddress_host_name = htmlspecialchars_uni(@gethostbyaddr($mybb->input['ipaddress']));
				
				// gethostbyaddr returns the same ip on failure
				if($ipaddress_host_name == $mybb->input['ipaddress'])
				{
					$ipaddress_host_name = '';
				} else {$ipaddress_host_name .= "<br />";}
				
				/* end copy from modcp.php */
					
				//add this session to the sessions table
				
				if($row['sid'] == $session->sid)
				{
					$delete = " <img src=\"http://images-1.findicons.com/files/icons/1156/fugue/16/tick_circle_frame.png\" alt=\"This is your session.\" title=\"This is your session.\"/>";
				} else {
					$delete = '';
				}
				
				$sessions .= "\n<tr>
				<td class=\"trow2\">{$userlink}</td>
				<td class=\"trow2\">{$row['sid']}{$delete}</td>
				<td class=\"trow2\"><a href=\"http://{$row['ip']}.ipaddress.com/\" target=\"_blank\">{$row['ip']}</a><a href=\"usercp.php?action=mysessions&amp;ip={$row['ip']}\"> <img src=\"http://icons.iconarchive.com/icons/deleket/scrap/16/Magnifying-Glass-icon.png\" alt=\"Search\" /></a> {$ipaddress_location}{$ipaddress_host_name}</a></td>
				<td class=\"trow2\"><abbr title=\"".htmlspecialchars_uni($row['useragent'])."\">{$useragent}</abbr></td>
				<td class=\"trow2\">{$wol}</td>
				<td class=\"trow2\"><a href=\"usercp.php?action=mysessions&amp;do=manage_mysessions&amp;delete={$row['sid']}&amp;hash={$mybb->post_code}\"><img src=\"http://icons.iconarchive.com/icons/famfamfam/silk/16/door-in-icon.png\" alt=\"Logout\" /></a></td>
				</tr>";

			}
	
		} else {
			//show sessions pending deletion
			
			//query
			$query = $db->query("SELECT * FROM ".TABLE_PREFIX."mysessions_kill{$extra}{$limit}");
			$allq = $db->query("SELECT * FROM ".TABLE_PREFIX."mysessions_kill{$extra}");	
			
			$colspan = '4';
			
			$sessions = "<tr>
			<td class=\"tcat\" width=\"5\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>Username</strong></span></td>
			<td class=\"tcat\" width=\"85\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>SID</strong></span></td>
			<td class=\"tcat\" width=\"85\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>Time Requested</strong></span></td>
			<td class=\"tcat\" width=\"85\" align=\"center\" style=\"white-space: nowrap\"><span class=\"smalltext\"><strong>Cancel Request</strong></span></td>
			</tr>";
			
			//display the sessions
			while($row = $db->fetch_array($query))
			{
				$user = get_user($row['uid']);
				$sessions .= "\n<tr>
				<td class=\"trow2\">{$user['username']}</td>
				<td class=\"trow2\">{$row['sid']}</td>
				<td class=\"trow2\">".my_date('F j, Y, g:i a',$row['timestamp'])."</td>
				<td class=\"trow2\"><a href=\"usercp.php?action=mysessions&amp;do=manage_mysessions&amp;cancel={$row['sid']}&amp;hash={$mybb->post_code}\"><img src=\"http://icons.iconarchive.com/icons/oxygen-icons.org/oxygen/16/Actions-dialog-cancel-icon.png\" alt=\"Cancel\"/></a></td>
				</tr>";
			}
	
		}			

	
		//get multipage using defualt MyBB function
		$multipage = multipage($db->num_rows($allq), 10, $pagenum, "usercp.php?action=mysessions&amp;page={page}{$eurl}");
	
		//search username box
		$searchbox = "<form action=\"usercp.php\" method=\"get\">
<input type=\"text\" class=\"textbox\" name=\"username\" size=\"25\" />
<input type=\"hidden\" name=\"do\" value=\"search_mysessions\"/>
<input type=\"submit\"	/>
</form>";	

		/* And here we are, the full MySessions template.
		* I didn't use the MyBB template system because
		* I anticipated frequesnt updates to the plugin,
		* and handling template updates can be messy.
		* Also, there really isn't much people should
		* need to edit.
		*/
		$template = "<html>
<head>
<title>{$lang->user_cp}</title>
{$headerinclude}
</head>
<body>
{$header}
<table width=\"100%\" border=\"0\" align=\"center\">
<tr>
{$usercpnav}
<td valign=\"top\">
{$errors}
<table border=\"0\" cellspacing=\"{$theme['borderwidth']}\" cellpadding=\"{$theme['tablespace']}\" class=\"tborder\">
<tr>
<td class=\"thead\" colspan=\"{$colspan}\"><strong>MySessions</strong> (<a href=\"usercp.php?action=mysessions\">View Live Sessions</a> | <a href=\"usercp.php?action=mysessions&view=pending\">View Sessions Pending Cancellation</a>)</td>
</tr>
<tr>
{$sessions}
</tr>
</table>
{$multipage}<br />
{$searchbox}
</td>
</tr>
</table>
{$footer}
</body>
</html>";

		//spit out the page!
		output_page($template);

	}		
}


//print an alert if there are multiple sessions logged in!
function mysessions_multiple_alert($page)
{
	global $mybb,$db;
	
	//the user wants to ignore the fact there are multiple sessions?
	if(isset($mybb->input['mysessions-multiple-ignore']))
	{
		//well okay, but he can only ignore for a day.
		my_setcookie("mysessions_multiple_ignore","true",86400);
		$mybb->cookies['mysessions_multiple_ignore'] = true;
	}
	
	//if the user isn't a guest, can view MySessions, and they're not ignoring the alert
	if($mybb->user['uid'] != '0' && mysession_access_level() != 0 && !isset($mybb->cookies['mysessions_multiple_ignore']))
	{
		//get sessions for this uid
		$query = $db->simple_select("sessions","*","uid='{$mybb->user['uid']}'");
		
		//is there more than one session?
		if($db->num_rows($query) > 1)
		{
			//yes there is, display an alert!
			$page = str_replace("<div id=\"content\">","<div id=\"content\"><div class=\"red_alert\"><img src=\"http://icons.iconarchive.com/icons/famfamfam/silk/16/exclamation-icon.png\" alt=\"Warning\"/>&nbsp; There are ".$db->num_rows($query)." sessions with your account! <a href=\"usercp.php?action=mysessions\">View Sessions</a> | <a href=\"?mysessions-multiple-ignore\">Ignore</a> </div>",$page);
		}
	}
	
	return $page;
}

//get the access level of the user to see what parts of MySessions they can use
function mysession_access_level()
{
	global $mybb;
	
	//ordinary users who can only manage their own sessions
	$normperm = explode(",",$mybb->settings['mysessions_normgroups']);
	//super users who can do whatever the hell they want
	$superperm = explode(",",$mybb->settings['mysessions_supergroups']);

	//by default, no one can see anything
	$permlevel = 0;
	
	//is this a normal user?
	if(in_array($mybb->user['usergroup'],$normperm)) {$permlevel = 1;}
	//or is he a super user?
	if(in_array($mybb->user['usergroup'],$superperm)) {$permlevel = 2;}
	
	/* Note: if a usergroup is in both settings, the superuser setting overrrides the normal. */
		
	return $permlevel;
}

//bye bye!
?>
