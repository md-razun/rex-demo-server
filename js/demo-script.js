jQuery(document).ready(function($){
    $(document).on('click','.rex-watch-demo-btn',function(e){
        e.preventDefault();
        var button = $(this);
        var plugin = button.data('plugin');

        console.log('Demo button clicked for plugin:', plugin); // Debug

        button.prop('disabled',true).text('Creating demo...');

        $.ajax({
            url: window.rex_demo_ajax.ajax_url,
            type:'POST',
            data:{
                action:'rex_create_demo_site',
                plugin: plugin,
                security: window.rex_demo_ajax.nonce
            },
            success:function(res){
                console.log('AJAX response:', res); // Debug
                if(res.success && res.data.url){
                    window.location.href = res.data.url;
                } else {
                    alert(res.data || 'Failed to create demo.');
                    button.prop('disabled',false).text('Watch Demo');
                }
            },
            error:function(xhr,status,error){
                console.error('AJAX error:', status, error);
                alert('Connection error. Try again.');
                button.prop('disabled',false).text('Watch Demo');
            }
        });
    });
});
