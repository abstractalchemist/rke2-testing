import aws_cdk as core
import aws_cdk.assertions as assertions

from rke2_testing.rke2_testing_stack import Rke2TestingStack

# example tests. To run these tests, uncomment this file along with the example
# resource in rke2_testing/rke2_testing_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = Rke2TestingStack(app, "rke2-testing")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
