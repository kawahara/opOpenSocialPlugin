<?php if (!Doctrine::getTable('SnsConfig')->get('is_use_outer_shindig', false)): ?>
<p class="flash">
<?php if (sfConfig::get('op_opensocial_is_allow_inner_container', false)): ?>
<?php echo __("The OpenSocial container is executed by the same domain as this SNS now."); ?>
<?php endif; ?>
<?php echo __("You should configure to outer domain container for reason of security when this SNS is production operation.") ?>
<br />
<a href="http://redmine.openpne.jp/projects/plg-open-social/wiki/" target="_blank"><?php echo __('See document') ?></a>
</p>
<?php endif; ?>
