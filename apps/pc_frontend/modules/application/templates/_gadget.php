<div class="dparts box"><div class="parts">
<div id="gadgets-gadget-title-bar-<?php echo $mid ?>" class="partsHeading">
<p class="link"><?php 
if ($isViewer)
{
  if ($hasSetting)
  {
    echo link_to_app_setting(__('設定'), $mid, true);
  }
}
else
{
  echo link_to(__('このアプリを追加する'),"application/add?id=".$aid);
}
?></p>
<h3 id="remote_iframe_<?php echo $mid ?>_title"><?php echo $title ?></h3>
</div>
<div class="block">
<iframe width="100%" scrolling="<?php
if ($scrolling)
{
  echo "on";
}
else
{
  echo "off";
}
?>" height="<?php echo ($height) ?>" frameborder="no" src="<?php echo $iframeUrl ?>" class="gadgets-gadget" name="remote_iframe_<?php echo $mid ?>" id="remote_iframe_<?php echo $mid ?>"></iframe>
</div>
</div></div>
