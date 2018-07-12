import React from 'react';

import './PostHeader.css'
import PostTags from './PostTags/PostTags';

class PostHeader extends React.Component {
    getTitleBlock() {
        if (!this.props.title) {
            return (
                <div className={"skeleton-container"}>
                    <h1 className={'bp3-skeleton title ' + this.props.className}>Lorem ipsum dolor sit amet</h1>
                </div>
            );
        }
        return <h1 className="title">{this.props.title}</h1>
    }

    render() {
        return (
            <div className={this.props.className}>
                {this.getTitleBlock()}
                <PostTags className="post-tags" tags={this.props.tags}/>
            </div>
        )
    }
}

export default PostHeader;