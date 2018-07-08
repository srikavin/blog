import React from "react";

import './PostContent.css'
import MathRenderer from "./MathRenderer/MathRenderer";

const loremIpsum = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ac pharetra est, quis venenatis dui." +
    " Etiam eros purus, accumsan sed risus eget, pulvinar lobortis odio. Integer mattis a sem vel molestie. Quisque" +
    " gravida justo tellus, nec maximus arcu lobortis vitae. Phasellus tempus leo ac tortor aliquet fringilla. Morbi " +
    "semper lorem vitae quam sagittis, et consequat dui efficitur. Pellentesque eros arcu, interdum at dui a, semper" +
    " varius velit. Donec arcu justo, sodales semper feugiat in, fringilla pharetra tortor. Curabitur ut quam quam. " +
    "Vivamus rhoncus augue sit amet arcu pulvinar ultricies. Vestibulum eu dolor vel neque fringilla vulputate a sed" +
    " lorem. Nulla bibendum dui vitae dapibus commodo.";

class PostContent extends React.Component {
    genLoremIpsum() {
        let paragraphs = [];
        for (let i = 0; i < 10; i++) {
            paragraphs.push(<p key={i} className={"pt-skeleton"}>{loremIpsum + loremIpsum}<br/></p>);
        }
        return paragraphs;
    }

    getContentBlock(input) {
        if (!this.props.content) {
            return this.genLoremIpsum().map(e => e);

        }
        return (
            <span>
                <MathRenderer source={input}/>
            </span>
        );
    }

    render() {
        return (
            <div className={"content " + this.props.className}>
                {this.getContentBlock(this.props.content)}
            </div>
        );
    }
}

export default PostContent;