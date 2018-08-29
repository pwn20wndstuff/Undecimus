#import "RollectraGradientView.h"
#import <QuartzCore/QuartzCore.h>

@implementation RollectraGradientView

- (instancetype)initWithCoder:(NSCoder *)aDecoder {
    self = [super initWithCoder:aDecoder];
    if (self){
        CAGradientLayer *layer = (CAGradientLayer *)self.layer;
        layer.startPoint = CGPointMake(0.5, 0);
        layer.endPoint = CGPointMake(0.5, 1);
        layer.colors = @[(id)[[UIColor colorWithRed:58.0f/255.0f green:70.0f/255.0f blue:91.0f/255.0f alpha:1.0f] CGColor], (id)[[UIColor colorWithRed:83.0f/255.0f green:105.2f/255.0f blue:118.3f/255.0f alpha:1.0f] CGColor]];
    }
    return self;
}

+ (Class)layerClass {
    return [CAGradientLayer class];
}

/*
// Only override drawRect: if you perform custom drawing.
// An empty implementation adversely affects performance during animation.
- (void)drawRect:(CGRect)rect {
    // Drawing code
}
*/

@end
